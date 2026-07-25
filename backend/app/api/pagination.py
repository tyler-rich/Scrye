"""The shared list-response envelope for the API layer.

Every endpoint that returns a **collection of persisted resources** answers with
``{"total": <int>, "items": [...]}`` — the :class:`Page` model below — rather
than a bare JSON array. That holds whether or not the endpoint paginates:

* Paginated endpoints (``/api/scans/history``, ``/api/scans/{id}/findings``,
  ``/api/audit``) report the number of rows *matching the query* in ``total``,
  which is what tells a client when the pages are exhausted.
* Unpaginated endpoints return the whole collection in one page via
  :func:`full_page`, where ``total == len(items)`` by construction.

**Where the line falls (L13 / APIR-8).** The envelope marks *persisted resource
collections* — rows that grow with usage, where a count is a meaningful answer
and pagination is a plausible future need. Endpoints that return a **fixed
enumeration** or **live, non-persisted data** deliberately keep returning a bare
array, because ``total`` there answers a question nobody asks. A new endpoint's
shape should be derivable from that rule; the current bare-array exceptions are
named explicitly in ``CONTRIBUTING.md`` § API conventions so a future review
reads them as a decision rather than as drift.

Enveloping the unpaginated lists also keeps adding pagination *additive* later:
a ``limit``/``offset`` query parameter can be introduced without changing the
response shape a consumer already parses.
"""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import BaseModel


class Page[ItemT](BaseModel):
    """A list response: the rows plus the total number of matching rows.

    ``total`` is the size of the *full* result set, not of ``items`` — for a
    paginated endpoint the two differ whenever more than one page matches. For
    an unpaginated endpoint built with :func:`full_page` they are always equal.
    """

    total: int
    items: list[ItemT]


def full_page[ItemT](items: Sequence[ItemT]) -> Page[ItemT]:
    """Wrap a fully-materialized collection as a single complete page.

    For unpaginated endpoints: the caller has already loaded every row, so the
    total is simply the length. Using this instead of constructing :class:`Page`
    by hand keeps ``total`` and ``items`` from drifting apart at a call site.
    """
    return Page(total=len(items), items=list(items))
