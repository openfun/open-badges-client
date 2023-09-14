# OBC, the Open Badges Client

`obc` is a python library that provides a standard API to interact with Open
Badge platforms.

## Quick start guide

### Install OBC

`obc` is distributed as a python package. It can be installed using `pip` (or
any other package manager) from PyPI:

```
$ pip install obc
```

### Use providers in your application

Let say you want to issue an existing Open Badge Factory badge for a list of
recipients, an example implementation would look like:

```python
from obc.providers.obf import BadgeIssue, BadgeQuery, OBF

# Configure Open Badge Factory provider using your client identifier and secret
# key
obf = OBF(client_id="my_obf_client_id", client_secret="super_secret")

# Get the badge with the "badge_id" identifier
badge = await anext(obf.badges.read(query=BadgeQuery(id="badge_id")))

# We want to issue a badge for the following recipients
issue = BadgeIssue(
    recipient=[
      "jane@example.org",
      "tarzan@example.org"
    ]
)

issue = await obf.badges.issue(badge, issue)
```

More details will follow in the upcoming documentation.

### Hack on the project

If you want to start contributing on the project, use the `bootstrap` Makefile
target to build the Docker development image:

```
$ make bootstrap
```

To run tests, type:

```
$ make test
```

And to lint sources, there is also a command for that:

```
$ make lint
```

If you had new dependencies to the project, you will have to rebuild the Docker
image (and the development environment):

```
$ make build && make dev
```

You can explore all other target using:

```
$ make help
```

## Contributing

This project is intended to be community-driven, so please, do not hesitate to
get in touch if you have any question related to our implementation or design
decisions.

We try to raise our code quality standards and expect contributors to follow
the recommandations from our
[handbook](https://openfun.gitbooks.io/handbook/content).

## License

This work is released under the MIT License (see [LICENSE](./LICENSE)).
