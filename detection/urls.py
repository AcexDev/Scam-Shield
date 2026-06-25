from .views import AnalyzeView, StatsView, ReportToAuthorityView
from django.urls import path

urlpatterns = [
    path('analyze/', AnalyzeView.as_view(), name='analyze'),
    path('stats/', StatsView.as_view(), name='stats'),
    path('report/', ReportToAuthorityView.as_view(), name='report'),
]