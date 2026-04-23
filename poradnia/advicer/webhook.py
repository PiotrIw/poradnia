import hmac
import json
import os


from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import JsonResponse
from django.utils.dateparse import parse_datetime
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from poradnia.cases.models import Case
from poradnia.teryt.models import JST

from .models import Advice, Area, InstitutionKind, Issue, PersonKind


def _json_error(code, message, status, fields=None):
    payload = {"status": "error", "error": {"code": code, "message": message}}
    if fields:
        payload["error"]["fields"] = fields
    return JsonResponse(payload, status=status)


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_required_id_list(payload, field, errors):
    if field not in payload:
        errors[field] = ["This field is required."]
        return []

    value = payload[field]
    if not isinstance(value, list):
        errors[field] = ["Must be a list of integers."]
        return []

    if not value:
        errors[field] = ["This list may not be empty."]
        return []

    if any(not _is_int(x) for x in value):
        errors[field] = ["All items must be integers."]
        return []

    return value


def _check_token(request):
    configured = getattr(settings, "ADVICER_WEBHOOK_BEARER_TOKEN", "") or os.getenv(
        "ADVICER_WEBHOOK_BEARER_TOKEN", ""
    )
    if not configured:
        return _json_error("webhook_not_configured", "Token not configured.", 503)

    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return _json_error("unauthorized", "Missing bearer token.", 401)

    token = auth.removeprefix("Bearer ").strip()
    if not hmac.compare_digest(token, configured):
        return _json_error("unauthorized", "Invalid bearer token.", 401)

    return None


def _parse_payload(request):
    try:
        data = json.loads(request.body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, _json_error("invalid_json", "Invalid JSON.", 400)

    if not isinstance(data, dict):
        return None, _json_error("invalid_payload", "Must be JSON object.", 400)

    return data, None


def _validate_payload(payload):
    errors = {}

    if "subject" not in payload or not isinstance(payload["subject"], str):
        errors["subject"] = ["This field is required and must be string."]
    elif not payload["subject"].strip():
        errors["subject"] = ["This field may not be blank."]

    for field in ["institution_kind_id", "jst_id"]:
        if field not in payload or not _is_int(payload[field]):
            errors[field] = ["This field is required and must be integer."]

    issue_ids = _validate_required_id_list(payload, "issue_ids", errors)
    area_ids = _validate_required_id_list(payload, "area_ids", errors)

    return errors, issue_ids, area_ids


def _resolve_relations(payload, issue_ids, area_ids, errors):
    resolved = {}
    User = get_user_model()

    fk_map = [
        ("advicer_id", "advicer", User, False),
        ("created_by_id", "created_by", User, False),
        ("modified_by_id", "modified_by", User, True),
        ("person_kind_id", "person_kind", PersonKind, True),
        ("institution_kind_id", "institution_kind", InstitutionKind, False),
        ("jst_id", "jst", JST, False),
    ]

    for key, attr, model, allow_null in fk_map:
        if key not in payload:
            continue

        val = payload[key]
        if val is None:
            if not allow_null:
                errors[key] = ["Cannot be null."]
            continue

        obj = model.objects.filter(pk=val).first()
        if not obj:
            errors[key] = [f"{model.__name__} not found."]
            continue

        if key == "advicer_id" and not obj.is_staff:
            errors[key] = ["Advicer must be staff."]
            continue

        resolved[attr] = obj

    issue_map = Issue.objects.in_bulk(issue_ids)
    if set(issue_ids) != set(issue_map):
        errors["issue_ids"] = ["Invalid issue ids."]
    else:
        resolved["issues"] = list(issue_map.values())

    area_map = Area.objects.in_bulk(area_ids)
    if set(area_ids) != set(area_map):
        errors["area_ids"] = ["Invalid area ids."]
    else:
        resolved["area"] = list(area_map.values())

    return resolved


def _get_or_create_advice(payload):
    advice_id = payload.get("advice_id")
    case_id = payload.get("case_id")

    advice = None
    if advice_id:
        advice = Advice.objects.filter(pk=advice_id).first()
        if not advice:
            return None, _json_error("advice_not_found", "Advice not found.", 404)

    if not advice and case_id:
        advice = Advice.objects.filter(case_id=case_id).first()

    created = advice is None
    return advice or Advice(), created


@method_decorator(csrf_exempt, name="dispatch")
class AdviceWebhookUpsertView(View):
    def post(self, request, *args, **kwargs):
        err = _check_token(request)
        if err:
            return err

        payload, err = _parse_payload(request)
        if err:
            return err

        errors, issue_ids, area_ids = _validate_payload(payload)
        if errors:
            return _json_error("validation_error", "Invalid payload.", 400, errors)

        resolved = _resolve_relations(payload, issue_ids, area_ids, errors)
        if errors:
            return _json_error("validation_error", "Invalid relations.", 400, errors)

        advice, created = _get_or_create_advice(payload)
        if isinstance(created, JsonResponse):
            return created

        with transaction.atomic():
            if payload.get("case_id"):
                advice.case = Case.objects.filter(pk=payload["case_id"]).first()

            advice.subject = payload["subject"].strip()

            for f in ["comment", "helped", "visible"]:
                if f in payload:
                    setattr(advice, f, payload[f])

            if "grant_on" in payload:
                advice.grant_on = parse_datetime(payload["grant_on"])

            for attr, val in resolved.items():
                if attr not in ("issues", "area"):
                    setattr(advice, attr, val)

            advice.save()

            advice.issues.set(resolved["issues"])
            advice.area.set(resolved["area"])

        return JsonResponse(
            {
                "status": "ok",
                "result": "created" if created else "updated",
                "advice_id": advice.pk,
                "case_id": advice.case_id,
            },
            status=201 if created else 200,
        )
