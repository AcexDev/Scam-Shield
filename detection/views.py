from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import AnalyzeRequestSerializer
from .analyzer import analyze
from google.genai import errors as genai_errors
from django.db import models
from .models import ScamReport, ThreatActor, AuthorityReport
from .serializers import AnalyzeRequestSerializer, AuthorityReportSerializer

class AnalyzeView(APIView):

    def post(self, request):
        request_serializer = AnalyzeRequestSerializer(data=request.data)
        request_serializer.is_valid(raise_exception=True)

        data = request_serializer.validated_data

        try:
            if 'image' in data:
                image = data['image']
                result = analyze(image_bytes=image.read(), mime_type=image.content_type)
            elif 'audio' in data:
                audio = data['audio']
                result = analyze(audio_bytes=audio.read(), audio_mime_type=audio.content_type)
            elif 'url' in data:
                result = analyze(url=data['url'])
            else:
                result = analyze(content=data['content'])

        except ValueError as e:
            return Response({"error": str(e)}, status=status.HTTP_502_BAD_GATEWAY)      

        except (ValueError, genai_errors.ServerError, genai_errors.ClientError) as e:
            return Response({"error": str(e)}, status=status.HTTP_502_BAD_GATEWAY)

        return Response(result, status=status.HTTP_200_OK)

from .models import ScamReport, ThreatActor

class StatsView(APIView):

    def get(self, request):
        total_scans = ScamReport.objects.aggregate(
            total=models.Sum('report_count')
        )['total'] or 0

        top_categories = (
            ScamReport.objects
            .values('fraud_category')
            .annotate(count=models.Sum('report_count'))
            .order_by('-count')[:5]
        )

        top_actors = (
            ThreatActor.objects
            .order_by('-report_count')[:5]
            .values('contact_type', 'contact_value', 'label', 'report_count')
        )

        return Response({
            "total_scans": total_scans,
            "top_fraud_categories": list(top_categories),
            "top_threat_actors": list(top_actors),
        })
    

class ReportToAuthorityView(APIView):

    def post(self, request):
        serializer = AuthorityReportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data

        try:
            scam_report = ScamReport.objects.get(fingerprint=data['scam_fingerprint'])
        except ScamReport.DoesNotExist:
            return Response(
                {"error": "Scam report not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        AuthorityReport.objects.create(
            scam_report=scam_report,
            agency=data['agency'],
            reporter_note=data.get('reporter_note', '')
        )

        return Response({
            "message": f"Report submitted to {data['agency']} successfully.",
            "agency": data['agency'],
            "scam_category": scam_report.fraud_category,
            "threat_level": scam_report.threat_level,
        }, status=status.HTTP_201_CREATED)
    
