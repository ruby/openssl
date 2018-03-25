# Contributing to Ruby OpenSSL

Thank you for your interest in contributing to Ruby OpenSSL!

This documentation provides an overview how you can contribute.

## Bugs and feature requests

Bugs and feature requests are tracked on [GitHub].

If you think you found a bug, file a ticket on GitHub. Please DO NOT report
security issues here, there is a separate procedure which is described on
["Security at ruby-lang.org"](https://www.ruby-lang.org/en/security/).

When reporting a bug, please make sure you include: 
* Ruby version 
* OpenSSL gem version
* OpenSSL library version 
* A sample file that illustrates the problem or link to the repository or 
  gem that is associated with the bug.

There are a number of unresolved issues and feature requests for openssl that
need review. Before submitting a new ticket, it is recommended to check
[known issues] and [bugs.ruby-lang.org], the previous issue tracker.

## Submitting patches

Patches are also very welcome!

Please submit a [pull request] with your changes.

Make sure that your branch does:

* Have good commit messages
* Follow Ruby's coding style ([DeveloperHowTo])
* Pass the test suite successfully (see "Testing")
* Add an entry to [History.md] if necessary

## Testing

We have a test suite!

Test cases are located under the
[`test/`](https://github.com/ruby/openssl/tree/master/test) directory.

You can run it with the following three commands:

```
$ rake install_dependencies # installs rake-compiler, test-unit, ...
$ rake compile
$ rake test
```

### Docker

You can also use Docker Compose to run tests. It can be used to check that your
changes work correctly with various supported versions of Ruby and OpenSSL.

First, you need to install [Docker](https://www.docker.com/products/docker) and
[Docker Compose](https://www.docker.com/products/docker-compose) on your
computer.

If you're on MacOS or Windows, we recommended to use the official [Docker
Toolbox](https://www.docker.com/products/docker-toolbox). On Linux, follow the
instructions for your package manager. For further information, please check
the [official documentation](https://docs.docker.com/).

Once you have Docker and Docker Compose, running the following commands will
build the container and execute the openssl tests. In this example, we will use
Ruby version 2.3 with OpenSSL version 1.0.2.

```
$ docker-compose build
$ export RUBY_VERSION=ruby-2.3
$ export OPENSSL_VERSION=openssl-1.0.2
$ docker-compose run test

# You may want an interactive shell for dubugging
$ docker-compose run debug
```

All possible values for `RUBY_VERSION` and `OPENSSL_VERSION` can be found in
[`.travis.yml`](https://github.com/ruby/openssl/tree/master/.travis.yml).

**NOTE**: these commands must be run from the openssl repository root, in order
to use the
[`docker-compose.yml`](https://github.com/ruby/openssl/blob/master/docker-compose.yml)
file we have provided.

This Docker image is built using the
[Dockerfile](https://github.com/ruby/openssl/tree/master/tool/ruby-openssl-docker)
provided in the repository.


## Relation with Ruby source tree

After Ruby 2.3, `ext/openssl` was converted into a "default gem", a library
which ships with standard Ruby builds but can be upgraded via RubyGems. This
means the development of this gem has migrated to a [separate
repository][GitHub] and will be released independently.

The version included in the Ruby source tree (trunk branch) is synchronized with
the latest release.

## Release policy

Bug fixes (including security fixes) will be made only for the version series
included in a stable Ruby release.

## Security

If you discovered a security issue, please send us in private, using the
security issue handling procedure for Ruby core.

You can either use [HackerOne] or send an email to security@ruby-lang.org.

Please see [Security] page on ruby-lang.org website for details.

Reported problems will be published after a fix is released.

_Thanks for your contributions!_

  _\- The Ruby OpenSSL team_

[GitHub]: https://github.com/ruby/openssl
[known issues]: https://github.com/ruby/openssl/issues
[bugs.ruby-lang.org]: https://bugs.ruby-lang.org/issues?utf8=%E2%9C%93&set_filter=1&f%5B%5D=status_id&op%5Bstatus_id%5D=o&f%5B%5D=assigned_to_id&op%5Bassigned_to_id%5D=%3D&v%5Bassigned_to_id%5D%5B%5D=7150&f%5B%5D=&c%5B%5D=project&c%5B%5D=tracker&c%5B%5D=status&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=updated_on&group_by=&t%5B%5D=
[DeveloperHowTo]: https://bugs.ruby-lang.org/projects/ruby/wiki/DeveloperHowto
[HackerOne]: https://hackerone.com/ruby
[Security]: https://www.ruby-lang.org/en/security/
[pull request]: https://github.com/ruby/openssl/compare
[History.md]: https://github.com/ruby/openssl/tree/master/History.md
