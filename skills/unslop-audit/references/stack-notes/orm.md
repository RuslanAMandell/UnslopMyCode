# Prisma, Drizzle, and query builders

- **Indexes.** Neither Prisma nor Drizzle creates an index because you filter on
  a column. Compare every `where`, `orderBy`, and join key against the declared
  indexes in the schema or migration.
- **N+1.** `findMany` followed by a per-row `findUnique` in a loop is the default
  shape generated code takes. Prisma's `include`/`select` and Drizzle's `with`
  do it in one query.
- **Mass assignment.** `data: body` in a create or update writes every field the
  caller sent, including ones not in your form.
- **Raw escapes.** `$queryRawUnsafe` and `sql.raw()` bypass parameterization
  entirely. `$queryRaw` with a tagged template is safe; the same string built
  with `+` is not.
- **Connection pooling.** Serverless plus a connection-per-invocation client
  exhausts the database's connection limit under modest traffic. Look for a
  pooler URL or a singleton client.
- `select *` (`select: undefined`) pulls every column, including ones you added
  later such as password hashes and internal notes.
