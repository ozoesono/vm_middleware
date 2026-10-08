"""Tests for the Celery app wiring: broker config and Beat schedule."""

from src.celery_app import _build_beat_schedule, _crontab, celery_app
from src.common.config import AppConfig, AppSettings, ScheduleConfig, get_config


def _config_with_schedule(**schedule_kwargs) -> AppConfig:
    config = AppConfig(settings=AppSettings(database_url="sqlite:///:memory:", config_dir="config"))
    config.schedule = ScheduleConfig(**schedule_kwargs)
    return config


class TestCrontabParsing:
    def test_standard_cron_expression(self):
        sched = _crontab("30 5 * * *")
        assert sched.minute == {30}
        assert sched.hour == {5}

    def test_weekday_and_wildcards(self):
        sched = _crontab("0 6 * * 1-5")
        assert sched.minute == {0}
        assert sched.hour == {6}
        assert sched.day_of_week == {1, 2, 3, 4, 5}


class TestBeatSchedule:
    def test_all_entries_present_when_enabled(self):
        config = _config_with_schedule(
            cron="0 6 * * *",
            enabled=True,
            nvd_interval_minutes=60,
            maintenance_cron="30 5 * * *",
        )
        schedule = _build_beat_schedule(config)

        assert set(schedule) == {
            "run-pipeline", "nvd-enrichment", "maintenance", "jira-sync", "exclusion-refresh",
        }
        assert schedule["exclusion-refresh"]["task"] == "src.tasks.refresh_exclusions_task"
        assert schedule["exclusion-refresh"]["schedule"] == 60.0
        assert schedule["jira-sync"]["task"] == "src.tasks.sync_jira_task"
        assert schedule["jira-sync"]["schedule"] == 60.0
        assert schedule["run-pipeline"]["task"] == "src.tasks.run_pipeline_task"
        assert schedule["run-pipeline"]["schedule"].hour == {6}
        assert schedule["nvd-enrichment"]["schedule"] == 3600.0
        assert schedule["maintenance"]["task"] == "src.tasks.maintenance_task"
        assert schedule["maintenance"]["schedule"].minute == {30}

    def test_pipeline_omitted_when_disabled(self):
        config = _config_with_schedule(enabled=False)
        schedule = _build_beat_schedule(config)

        assert "run-pipeline" not in schedule
        # NVD and maintenance always run — they are cheap and resumable.
        assert set(schedule) == {"nvd-enrichment", "maintenance", "jira-sync", "exclusion-refresh"}

    def test_nvd_interval_converted_to_seconds(self):
        config = _config_with_schedule(nvd_interval_minutes=15)
        assert _build_beat_schedule(config)["nvd-enrichment"]["schedule"] == 900.0


class TestCeleryAppConfig:
    def test_broker_uses_configured_redis_url(self):
        assert celery_app.conf.broker_url == get_config().settings.redis_url

    def test_tasks_module_registered(self):
        assert "src.tasks" in celery_app.conf.include
