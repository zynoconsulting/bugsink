from django.contrib.auth import get_user_model
from django.urls import reverse

from bugsink.test_utils import TransactionTestCase25251 as TransactionTestCase
from events.factories import create_event, create_event_data
from issues.factories import get_or_create_issue
from projects.models import Project, ProjectMembership
from tags.models import store_tags


class IssueListEnvironmentFilterTests(TransactionTestCase):
    def setUp(self):
        super().setUp()
        self.user = get_user_model().objects.create_user(username="test")

        self.project = Project.objects.create(name="Project one")
        self.other_project = Project.objects.create(name="Project two")
        for project in [self.project, self.other_project]:
            ProjectMembership.objects.create(project=project, user=self.user, accepted=True)

        self.client.force_login(self.user)

        self.prod_issue = self._issue_in(self.project, "production", "ProdError")
        self.staging_issue = self._issue_in(self.project, "staging", "StagingError")
        self.other_prod_issue = self._issue_in(self.other_project, "production", "OtherProdError")

    def _issue_in(self, project, environment, calculated_type):
        issue, _ = get_or_create_issue(project=project, event_data=create_event_data(calculated_type))
        issue.calculated_type = calculated_type
        issue.calculated_value = "boom"
        issue.save()
        store_tags(create_event(project, issue), issue, {"environment": environment})
        return issue

    def test_project_issue_list_filters_by_environment(self):
        response = self.client.get(reverse("issue_list_open", kwargs={"project_pk": self.project.id}))
        self.assertContains(response, "ProdError")
        self.assertContains(response, "StagingError")

        response = self.client.get(
            reverse("issue_list_open", kwargs={"project_pk": self.project.id}), {"environment": "staging"})
        self.assertNotContains(response, "ProdError")
        self.assertContains(response, "StagingError")

    def test_global_issue_list_filters_by_environment_across_projects(self):
        response = self.client.get(reverse("global_issue_list_open"), {"environment": "production"})

        self.assertContains(response, "ProdError")
        self.assertContains(response, "OtherProdError")
        self.assertNotContains(response, "StagingError")

    def test_environment_dropdown_lists_the_environments_that_were_seen(self):
        response = self.client.get(reverse("issue_list_open", kwargs={"project_pk": self.project.id}))

        self.assertContains(response, '<option value="production"')
        self.assertContains(response, '<option value="staging"')
        self.assertContains(response, "All environments")

    def test_unknown_environment_is_ignored_rather_than_showing_nothing(self):
        response = self.client.get(
            reverse("issue_list_open", kwargs={"project_pk": self.project.id}), {"environment": "nonesuch"})

        self.assertContains(response, "ProdError")
        self.assertContains(response, "StagingError")

    def test_environment_filter_combines_with_search(self):
        # both filters apply: searching for the production issue while filtering on staging yields nothing
        url = reverse("issue_list_open", kwargs={"project_pk": self.project.id})

        response = self.client.get(url, {"environment": "staging", "q": "ProdError"})
        self.assertContains(response, "No open issues found")

        response = self.client.get(url, {"environment": "production", "q": "ProdError"})
        self.assertNotContains(response, "No open issues found")
