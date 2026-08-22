Two of these are shipped in 0.9.0, and I owe you a correction on a third.

**Shipped: the schema-wide grant.** You were right that this slips through review, and it also slipped through my scanner. The existing grant rules matched `ON <table>`, and `ON ALL TABLES IN SCHEMA public` has no table name between `ON` and `TO`, so it was structurally invisible. I wrote your exact line into a test repo, ran the previous release, and got "Nothing dangerous found". It is now critical when the target role is `anon`, `public` or `authenticated`, and stays quiet for `service_role`.

**Shipped, but not the way you described it: the write side.** The bug is real and it was a genuine miss, but the mechanism isn't a forgotten `WITH CHECK`. Per the CREATE POLICY docs, for `UPDATE` an omitted `WITH CHECK` falls back to the `USING` expression for new rows, and an `INSERT` policy cannot have a `USING` expression at all, so `WITH CHECK` is required and can't be forgotten. A rule for "missing WITH CHECK" would have fired on correct code.

What actually opens the write side is an **explicit** `WITH CHECK (true)` sitting beside a scoped `USING`, which is what shipped:

```sql
CREATE POLICY docs_update ON public.docs
  TO authenticated
  FOR UPDATE USING (auth.uid() = owner) WITH CHECK (true);
```

Reads are scoped, writes are not, any signed-in user can move a row to another owner. The good fixture now contains an UPDATE policy with `WITH CHECK` omitted plus a test asserting it stays silent, so the wrong version can't get reintroduced later.

If you're seeing the failure in production some other way, I'd like the shape of it, because the docs and my testing both say omission is safe.

**Your #2, predicate subqueries resolving through an unguarded table.** This is the best of the remaining three and I think it's tractable: collect which tables ever get `ENABLE ROW LEVEL SECURITY`, then flag a policy whose predicate subquery selects from a table not in that set. It fails on tables defined outside the repo, which the existing column rule already skips for the same reason. Next one I build unless you tell me it's the wrong shape.

**Your #3 and #5 I don't think I can do honestly from text.** Detecting that a `broadcast` payload carries row data means understanding what's in the payload, and storage policies lagging schema changes means knowing which bucket serves which table. Both are real, neither reduces to a diff pattern I trust, and I'd rather not ship a rule that guesses. Flagging them here in case someone reading has a sharper idea.

**On the temp-function vector:** agreed, and worth being precise that the `search_path` check only closes it when `SET search_path` actually excludes `pg_temp`, since `pg_temp` is searched first by default. A `REVOKE TEMPORARY ... FROM PUBLIC` check is a small rule and I'll take it.

Six of the twenty-two rules now exist because someone described a diff it missed. Yours are the first from anyone who does this professionally, and the correction above is only possible because you were specific enough to check.
