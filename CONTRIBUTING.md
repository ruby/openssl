# Contributing to Ruby OpenSSL

Thank you for your interest in contributing to Ruby OpenSSL!

This documentation provides an overview how you can contribute.

## Bugs and feature requests

Bugs and feature requests are tracked on [GitHub].

If you think you found a bug, file a ticket on GitHub. Please DO NOT report
security issues here, there is a separate procedure which is described on
["Security at ruby-lang.org"](https://www.ruby-lang.org/en/security/).

When reporting a bug, please make sure you include the version of Ruby, the
version of openssl gem, the version of the OpenSSL library, along with a sample
file that illustrates the problem or link to repository or gem that is
associated with the bug.

There is a number of unresolved issues and feature requests for openssl that
need review. Before submitting a new ticket, it is recommended to check
[known issues] and [bugs.ruby-lang.org], the previous issue tracker.

## Submitting patches

Patches are also very welcome!

Please submit a [pull request] with your changes.

Make sure that your branch does:

* Have good commit messages
* Follow Ruby's coding style ([DeveloperHowTo])
* Pass the test suite successfully (see "Testing")
* Add an entry to [History.rdoc] if necessary

## Testing

We have a test suite. You can run it with the following three commands:

```
$ gem install rake-compiler test-unit
$ rake compile
$ rake test
```

Test cases are located under `test/` directory.

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
[History.rdoc]: https://github.com/ruby/openssl/tree/master/History.rdoc
