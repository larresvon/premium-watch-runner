# Premium Watch hosted runner

This public repository contains only generic program code and a bounded GitHub Actions workflow. Personal monitoring settings, selected shops, watch targets, observations, delivery credentials, and run status belong in a separate private state repository.

The workflow supports two manual modes:

- **verify** checks the selected public sources from GitHub-hosted Linux. It does not save retailer results or send alerts.
- **scan** performs one bounded, resumable monitoring slice. The workflow triggers every two hours, but it checks shops only while hosting is armed and the PC heartbeat is stale. A slice can be partial; the private status page reports actual coverage.

The cloud job receives private state access and alert delivery only through separately managed Actions secrets. It does not upload artifacts or cache monitoring data. Public pull requests do not trigger the workflow.

Standard GitHub-hosted runners are free for public repositories. See [GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions) and the [hosted runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
