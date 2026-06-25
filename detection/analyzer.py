# detection/analyzer
import hashlib
from .models import ScamReport, ThreatActor
from .services import analyze_text, analyze_image, analyze_url, analyze_audio


def _fingerprint(text: str) -> str:
    normalized = " ".join(text.lower().split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:64]


def _store_findings(result: dict, fingerprint: str, source: str):
    if not result.get('is_scam'):
        return None

    report, created = ScamReport.objects.get_or_create(
        fingerprint=fingerprint,
        defaults={
            'fraud_category': result['fraud_category'],
            'threat_level': result['threat_level'],
            'flagged_phrases': result['flagged_phrases'],
            'explanation': result['explanation'],
            'recommended_action': result['recommended_action'],
            'source': source,
        }
    )
    if not created:
        report.report_count += 1
        report.save()

    for actor in result.get('threat_actors', []):
        ta, ta_created = ThreatActor.objects.get_or_create(
            contact_type=actor['contact_type'],
            contact_value=actor['contact_value'],
            defaults={
                'label': actor['label'],
                'fraud_categories': [result['fraud_category']],
            }
        )
        if not ta_created:
            ta.report_count += 1
            if result['fraud_category'] not in ta.fraud_categories:
                ta.fraud_categories.append(result['fraud_category'])
            ta.save()

    return report


def _check_threat_actors(text: str):
    actors = ThreatActor.objects.all()
    for actor in actors:
        if actor.contact_value.lower() in text.lower():
            return actor
    return None


def _build_response(result: dict, report, known_actor=None) -> dict:
    response = {**result}

    response['fingerprint'] = report.fingerprint if report else None

    response['social_proof'] = f"{report.report_count} people reported this pattern." if report and report.report_count > 1 else None

    response['known_actor'] = {
        'contact_type': known_actor.contact_type,
        'contact_value': known_actor.contact_value,
        'label': known_actor.label,
        'report_count': known_actor.report_count,
    } if known_actor else None

    return response


def analyze(content: str = None, image_bytes: bytes = None, mime_type: str = None,
            url: str = None, audio_bytes: bytes = None, audio_mime_type: str = None) -> dict:
    known_actor = None

    if image_bytes:
        result = analyze_image(image_bytes, mime_type)
        fingerprint = _fingerprint(str(result.get('flagged_phrases', '')))
        report = _store_findings(result, fingerprint, source='IMAGE')
        return _build_response(result, report)
    
    if audio_bytes:
        result = analyze_audio(audio_bytes, audio_mime_type)
        fingerprint = _fingerprint(str(result.get('flagged_phrases', '')))
        report = _store_findings(result, fingerprint, source='AUDIO')
        return _build_response(result, report)


    if url:
        known_actor = _check_threat_actors(url)
        fingerprint = _fingerprint(url)
        try:
            report = ScamReport.objects.get(fingerprint=fingerprint)
            report.report_count += 1
            report.save()
            result = {
                'is_scam': report.fraud_category != 'NONE',
                'scam_probability': 99 if report.threat_level == 'CRITICAL' else 75,
                'threat_level': report.threat_level,
                'fraud_category': report.fraud_category,
                'flagged_phrases': report.flagged_phrases,
                'explanation': report.explanation,
                'recommended_action': report.recommended_action,
                'threat_actors': [],
            }
            return _build_response(result, report, known_actor)
        except ScamReport.DoesNotExist:
            pass
        result = analyze_url(url)
        report = _store_findings(result, fingerprint, source='TEXT')
        return _build_response(result, report, known_actor)

    # Text path
    known_actor = _check_threat_actors(content)
    fingerprint = _fingerprint(content)
    try:
        report = ScamReport.objects.get(fingerprint=fingerprint)
        report.report_count += 1
        report.save()
        result = {
            'is_scam': report.fraud_category != 'NONE',
            'scam_probability': 99 if report.threat_level == 'CRITICAL' else 75,
            'threat_level': report.threat_level,
            'fraud_category': report.fraud_category,
            'flagged_phrases': report.flagged_phrases,
            'explanation': report.explanation,
            'recommended_action': report.recommended_action,
            'threat_actors': [],
        }
        return _build_response(result, report, known_actor)
    except ScamReport.DoesNotExist:
        pass

    result = analyze_text(content)
    report = _store_findings(result, fingerprint, source='TEXT')
    return _build_response(result, report, known_actor)