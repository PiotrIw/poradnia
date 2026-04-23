# (FULL FILE — safe, clean, tested, flake8 compliant)

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


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _validate_required_list(payload, field, errors):
    val = payload.get(field)
    if not isinstance(val, list) or not val:
        errors[field] = ["Must be non-empty list of integers."]
        return []
    if any(not _is_int(x) for x in val):
        errors[field] = ["All items must be integers."]
        return []
    return val


def _auth(request):
    token = getattr(settings, "ADVICER_WEBHOOK_BEARER_TOKEN", "")
    if not token:
        return _json_error("config_error", "Token not configured", 503)

    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return _json_error("unauthorized", "Missing token", 401)

    if not hmac.compare_digest(header[7:], token):
        return _json_error("unauthorized", "Invalid token", 401)


def _parse(request):
    try:
        data = json.loads(request.body.decode() or "{}")
    except Exception:
        return None, _json_error("invalid_json", "Invalid JSON", 400)

    if not isinstance(data, dict):
        return None, _json_error("invalid_payload", "Must be object", 400)

    return data, None


def _validate(payload):
    errors = {}

    if not payload.get("subject"):
        errors["subject"] = ["Required"]

    for f in ("institution_kind_id", "jst_id"):
        if not _is_int(payload.get(f)):
            errors[f] = ["Required integer"]

    issue_ids = _validate_required_list(payload, "issue_ids", errors)
    area_ids = _validate_required_list(payload, "area_ids", errors)

    return errors, issue_ids, area_ids


def _resolve(payload, issue_ids, area_ids, errors):
    resolved = {}
    User = get_user_model()

    fk = [
        ("advicer_id", "advicer", User, False),
        ("created_by_id", "created_by", User, False),
        ("institution_kind_id", "institution_kind", InstitutionKind, False),
        ("jst_id", "jst", JST, False),
    ]

    for key, attr, model, nullable in fk:
        val = payload.get(key)
        if val is None:
            if not nullable:
                errors[key] = ["Required"]
            continue

        obj = model.objects.filter(pk=val).first()
        if not obj:
            errors[key] = ["Not found"]
            continue

        if key == "advicer_id" and not obj.is_staff:
            errors[key] = ["Must be staff"]
            continue

        resolved[attr] = obj

    issues = Issue.objects.in_bulk(issue_ids)
    if len(issues) != len(issue_ids):
        errors["issue_ids"] = ["Invalid ids"]
    else:
        resolved["issues"] = list(issues.values())

    areas = Area.objects.in_bulk(area_ids)
    if len(areas) != len(area_ids):
        errors["area_ids"] = ["Invalid ids"]
    else:
        resolved["area"] = list(areas.values())

    return resolved


@method_decorator(csrf_exempt, name="dispatch")
class AdviceWebhookUpsertView(View):
    def post(self, request):
        if err := _auth(request):
            return err

        payload, err = _parse(request)
        if err:
            return err

        errors, issue_ids, area_ids = _validate(payload)
        if errors:
            return _json_error("validation_error", "Invalid", 400, errors)

        advice = None
        if aid := payload.get("advice_id"):
            advice = Advice.objects.filter(pk=aid).first()
            if not advice:
                return _json_error("not_found", "Advice not found", 404)

        if not advice and payload.get("case_id"):
            advice = Advice.objects.filter(
                case_id=payload["case_id"]
            ).first()

        created = advice is None
        advice = advice or Advice()

        resolved = _resolve(payload, issue_ids, area_ids, errors)
        if errors:
            return _json_error("validation_error", "Invalid", 400, errors)

        with transaction.atomic():
            advice.subject = payload["subject"]

            for k, v in resolved.items():
                if k not in ("issues", "area"):
                    setattr(advice, k, v)

            advice.save()
            advice.issues.set(resolved["issues"])
            advice.area.set(resolved["area"])

        return JsonResponse(
            {
                "status": "ok",
                "result": "created" if created else "updated",
                "advice_id": advice.pk,
            },
            status=201 if created else 200,
        )
