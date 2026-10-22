<!-- LOVABLE:BEGIN -->
> [!IMPORTANT]
> This project is connected to [Lovable](https://lovable.dev). Avoid rewriting
> published git history — force pushing, or rebasing/amending/squashing commits
> that are already pushed — as it rewrites history on Lovable's side and the
> user will likely lose their project history.
>
> Commits you push to the connected branch sync back to Lovable and show up in
> the editor, so keep the branch in a working state.
<!-- LOVABLE:END -->

## Project rules
- All feed/fetch logic lives in `src/lib/*.functions.ts` server functions; pages never call external feeds directly (CORS + keys stay server-side).
- Seed data lives in `src/lib/data.ts` until Lovable Cloud tables replace it; keep the risk score formula there with tests in `src/test/risk-score.test.ts`.
- Colors only via tokens in `src/styles.css` (severity tokens critical/high/medium/low, intel, ok).
