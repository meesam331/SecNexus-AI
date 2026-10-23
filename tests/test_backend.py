import io
import unittest
from unittest.mock import patch

import backend


class SecNexusApiTests(unittest.TestCase):
    def setUp(self):
        self.client = backend.app.test_client()

    def test_demo_result_is_unverified_and_unscored(self):
        with patch.object(backend, "VIRUSTOTAL_API_KEY", ""), patch.object(
            backend, "groq_client", None
        ):
            response = self.client.get("/api/intelligence/domain?value=example.com")

        self.assertEqual(response.status_code, 200)
        result = response.get_json()["result"]
        self.assertEqual(result["safetyStatus"], "NOT_VERIFIED")
        self.assertIsNone(result["score"]["score"])
        self.assertIn("not a safety verdict", result["score"]["factors"][0]["detail"])
        report = result["caseReport"]
        self.assertEqual(report["input_type"], "URL")
        self.assertIsNone(report["threat_score"])
        self.assertEqual(report["peca_sections_violated"], [])
        self.assertEqual(
            set(report),
            {
                "case_id", "input_type", "threat_score", "verdict", "confidence",
                "executive_summary_urdu", "technical_findings", "peca_sections_violated",
                "recommended_action_for_officer", "forensic_report_pdf_text",
            },
        )

    def test_mp4_report_does_not_claim_deepfake_analysis(self):
        with patch.object(backend, "VIRUSTOTAL_API_KEY", ""), patch.object(
            backend, "groq_client", None
        ):
            response = self.client.post(
                "/api/scan/file",
                data={"file": (io.BytesIO(b"sample video bytes"), "evidence.mp4", "video/mp4")},
                content_type="multipart/form-data",
            )

        self.assertEqual(response.status_code, 200)
        report = response.get_json()["result"]["caseReport"]
        self.assertEqual(report["input_type"], "DEEPFAKE_VIDEO")
        self.assertIn("No frames", report["technical_findings"]["apk_permissions_analysis"])
        self.assertIn("not observed or assessed", report["technical_findings"]["behavioral_analysis"])
        self.assertIsNone(report["threat_score"])

    def test_apk_and_whatsapp_inputs_are_classified_without_claiming_analysis(self):
        with patch.object(backend, "VIRUSTOTAL_API_KEY", ""), patch.object(
            backend, "groq_client", None
        ):
            apk_response = self.client.post(
                "/api/scan/file",
                data={"file": (io.BytesIO(b"not a real apk"), "sample.apk", "application/vnd.android.package-archive")},
                content_type="multipart/form-data",
            )
            url_response = self.client.post(
                "/api/scan/url", json={"url": "https://wa.me/123456789"}
            )

        apk_report = apk_response.get_json()["result"]["caseReport"]
        self.assertEqual(apk_report["input_type"], "APK")
        self.assertIn("was not decompiled", apk_report["technical_findings"]["apk_permissions_analysis"])
        self.assertEqual(url_response.get_json()["result"]["caseReport"]["input_type"], "WHATSAPP_LINK")

    def test_zero_detection_result_is_not_a_safety_guarantee(self):
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 8,
                        "undetected": 12,
                        "timeout": 0,
                    },
                    "last_analysis_results": {},
                }
            }
        }
        with patch.object(backend, "VIRUSTOTAL_API_KEY", "configured"), patch.object(
            backend, "query_vt_domain", return_value=vt_data
        ):
            response = self.client.get("/api/intelligence/domain?value=example.com")

        result = response.get_json()["result"]
        self.assertEqual(result["safetyStatus"], "NO_THREATS_FOUND")
        self.assertEqual(result["score"]["score"], 0)
        self.assertIn("does not establish", result["score"]["factors"][0]["detail"])
        self.assertEqual(result["aiIntelligence"]["how_it_works"]["mitre_attack"], [])
        self.assertIn("not prove", result["aiIntelligence"]["threat_overview"]["summary"])

    def test_zero_engine_response_does_not_create_a_live_verdict(self):
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "timeout": 0,
                    },
                    "last_analysis_results": {},
                }
            }
        }
        with patch.object(backend, "VIRUSTOTAL_API_KEY", "configured"), patch.object(
            backend, "query_vt_domain", return_value=vt_data
        ):
            response = self.client.get("/api/intelligence/domain?value=example.com")

        result = response.get_json()["result"]
        self.assertEqual(result["safetyStatus"], "NOT_VERIFIED")
        self.assertIsNone(result["score"]["score"])

    def test_timeout_only_response_is_not_a_live_verdict(self):
        vt_data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 0,
                        "undetected": 0,
                        "timeout": 20,
                    },
                    "last_analysis_results": {},
                }
            }
        }
        with patch.object(backend, "VIRUSTOTAL_API_KEY", "configured"), patch.object(
            backend, "query_vt_domain", return_value=vt_data
        ):
            response = self.client.get("/api/intelligence/domain?value=example.com")

        result = response.get_json()["result"]
        self.assertEqual(result["safetyStatus"], "NOT_VERIFIED")
        self.assertIsNone(result["score"]["score"])

    def test_score_factors_explain_the_formula_and_source(self):
        score = backend.score_for(
            {"malicious": 2, "suspicious": 1, "totalEngines": 20}
        )

        self.assertEqual(score["score"], 9)
        self.assertIn("round(85 × 2/20) = 8", score["factors"][0]["detail"])
        self.assertEqual(
            score["factors"][0]["source"],
            "VirusTotal v3 last_analysis_stats.malicious",
        )

    def test_invalid_domain_is_rejected(self):
        response = self.client.get("/api/intelligence/domain?value=not-a-domain")
        self.assertEqual(response.status_code, 400)


ThreatLensApiTests = SecNexusApiTests

if __name__ == "__main__":
    unittest.main()
