from rest_framework import serializers

class AnalyzeResponseSerializer(serializers.Serializer):
    is_scam = serializers.BooleanField()
    scam_probability = serializers.IntegerField()
    threat_level = serializers.CharField()
    fraud_category = serializers.CharField()
    flagged_phrases = serializers.ListField(child=serializers.CharField())
    explanation = serializers.CharField()
    recommended_action = serializers.CharField()
    fingerprint = serializers.CharField()

class AnalyzeRequestSerializer(serializers.Serializer):
    content = serializers.CharField(required=False)
    image = serializers.ImageField(required=False)
    url = serializers.URLField(required=False)
    audio = serializers.FileField(required=False)

    def validate(self, data):
        if not any(data.get(f) for f in ('content', 'image', 'audio', 'url')):
            raise serializers.ValidationError("Provide content, image, audio, or url.")
        return data


class AuthorityReportSerializer(serializers.Serializer):
    scam_fingerprint = serializers.CharField()
    agency = serializers.ChoiceField(choices=['EFCC', 'NITDA', 'CBN', 'NPF'])
    reporter_note = serializers.CharField(required=False, allow_blank=True)