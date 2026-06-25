#detection/services

from google import genai
from google.genai import types
from google.genai import errors as genai_errors
from django.conf import settings
import json

client = genai.Client(api_key=settings.BACKUP_KEY)
MODEL = "models/gemini-2.5-flash"

SYSTEM_PROMPT = """
You are ShieldAI, a scam detection engine specialized in Nigerian digital fraud.

You analyze messages, links, and text for scam indicators.

Always respond with ONLY valid JSON in this exact structure:
{
  "is_scam": true or false,
  "scam_probability": 0-100,
  "threat_level": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "fraud_category": "PHISHING" | "PRIZE_FRAUD" | "IMPERSONATION" | "INVESTMENT_FRAUD" | "ROMANCE_SCAM" | "NONE",
  "flagged_phrases": ["phrase1", "phrase2"],
  "explanation": "Plain English explanation of why this is or isn't a scam",
  "recommended_action": "What the user should do",
  "threat_actors": [
    {
      "contact_type": "PHONE" | "WHATSAPP" | "BANK_ACCOUNT" | "URL" | "EMAIL" | "ORG_NAME",
      "contact_value": "the actual value extracted",
      "label": "short description e.g. 'Fake MTN number'"
    }
  ]
}

If no threat actors are found, return an empty list for threat_actors.
You know Nigerian institutions (GTBank, Access Bank, MTN, EFCC, INEC, etc.) and local scam patterns.
Never add text outside the JSON. No markdown, no backticks.
"""

def _parse_gemini_response(raw_text: str) -> dict:
    """Parse Gemini's response, stripping markdown fences if present."""
    cleaned = raw_text.strip().removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(cleaned)


def analyze_text(content: str) -> dict:
    try:
        response = client.models.generate_content(
            model=MODEL,
            contents=content,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
            )
        )
        return _parse_gemini_response(response.text)

    except genai_errors.ClientError as e:
        raise ValueError(f"Gemini API error: {str(e)}")
    except json.JSONDecodeError:
        raise ValueError("Gemini returned malformed JSON")


def analyze_image(image_bytes: bytes, mime_type: str) -> dict:
    try:
        image_part = types.Part.from_bytes(data=image_bytes, mime_type=mime_type)
        text_part = types.Part.from_text(
            text="Analyze this image for scam indicators. Extract all visible text and evaluate it."
        )
        response = client.models.generate_content(
            model=MODEL,
            contents=types.Content(parts=[image_part, text_part]),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
            )
        )
        return _parse_gemini_response(response.text)

    except genai_errors.ClientError as e:
        raise ValueError(f"Gemini API error: {str(e)}")
    except json.JSONDecodeError:
        raise ValueError("Gemini returned malformed JSON")

import httpx

def fetch_url_content(url: str) -> str:
    """Fetch text content from a URL for analysis."""
    try:
        response = httpx.get(url, timeout=10, follow_redirects=True)
        # Strip HTML tags roughly — good enough for scam detection
        import re
        text = re.sub(r'<[^>]+>', ' ', response.text)
        text = re.sub(r'\s+', ' ', text).strip()
        return text[:3000]  # cap at 3000 chars to stay within token limits
    except Exception:
        return ""  # if fetch fails, fall back to URL-only analysis


def analyze_url(url: str) -> dict:
    """Analyze a URL — fetches page content then runs full scam analysis."""
    page_content = fetch_url_content(url)

    if page_content:
        prompt = f"URL: {url}\n\nPage content:\n{page_content}"
    else:
        prompt = f"Analyze this URL for scam indicators: {url}"

    response = client.models.generate_content(
        model=MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.1,
        )
    )
    return _parse_gemini_response(response.text)

def analyze_audio(audio_bytes: bytes, mime_type: str) -> dict:
    try:
        audio_part = types.Part.from_bytes(data=audio_bytes, mime_type=mime_type)
        text_part = types.Part.from_text(
            text="Transcribe and analyze this audio for scam indicators. "
                 "Pay attention to spoken phone numbers, bank details, urgency tactics, "
                 "and impersonation of banks, telecoms, or government agencies."
        )
        response = client.models.generate_content(
            model=MODEL,
            contents=types.Content(parts=[audio_part, text_part]),
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_PROMPT,
                temperature=0.1,
            )
        )
        return _parse_gemini_response(response.text)

    except genai_errors.ClientError as e:
        raise ValueError(f"Gemini API error: {str(e)}")
    except json.JSONDecodeError:
        raise ValueError("Gemini returned malformed JSON")