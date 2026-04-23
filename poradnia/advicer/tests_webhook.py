import json
from unittest.mock import MagicMock, patch

from django.test import TestCase, override_settings
from django.urls import reverse


@override_settings(ADVICER_WEBHOOK_BEARER_TOKEN="secret")
class AdviceWebhookViewTestCase(TestCase):
    def setUp(self):
        self.url = reverse("advicer:webhook-upsert")

    def post(self, payload, token="secret"):
        headers = {}
        if token is not None:
            headers["HTTP_AUTHORIZATION"] = f"Bearer {token}"
        return self.client.post(
            self.url,
            data=json.dumps(payload),
            content_type="application/json",
            **headers,
        )

    def test_missing_token(self):
        resp = self.post({}, token=None)
        self.assertEqual(resp.status_code, 401)

    def test_invalid_json(self):
        resp = self.client.post(
            self.url, data="not-json", content_type="application/json"
        )
        self.assertEqual(resp.status_code, 400)

    def test_required_fields(self):
        resp = self.post({"case_id": 1})
        self.assertEqual(resp.status_code, 400)
        self.assertIn("subject", resp.json()["error"]["fields"])

    def test_advice_not_found(self):
        resp = self.post(
            {
                "advice_id": 999,
                "subject": "x",
                "institution_kind_id": 1,
                "jst_id": 1,
                "issue_ids": [1],
                "area_ids": [1],
            }
        )
        self.assertEqual(resp.status_code, 404)

    @patch("poradnia.advicer.webhook._resolve_relations")
    @patch("poradnia.advicer.webhook._get_or_create_advice")
    def test_success_flow(self, mock_get, mock_resolve):
        advice = MagicMock()
        advice.pk = 123
        advice.case_id = None
        advice.get_absolute_url.return_value = "/advicer/123"
        advice.issues.set = MagicMock()
        advice.area.set = MagicMock()

        mock_get.return_value = (advice, True)
        mock_resolve.return_value = {"issues": [], "area": []}

        resp = self.post(
            {
                "advice_id": 1,
                "subject": "ok",
                "institution_kind_id": 1,
                "jst_id": 1,
                "issue_ids": [1],
                "area_ids": [1],
            }
        )

        self.assertEqual(resp.status_code, 201)
        self.assertEqual(resp.json()["advice_id"], 123)
