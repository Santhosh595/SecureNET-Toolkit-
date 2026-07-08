# PathProbe — LEARN.md

## What problem does PathProbe solve?

Web servers often expose useful (or sensitive) paths that aren't linked from the homepage: admin
panels, backup archives, `.env` files, API roots. Tools like feroxbuster find them by trying a
list of likely names. PathProbe shows the core technique with a simple thread pool.

## Key concept — status-code filtering

Most guesses return `404 Not Found` (noise). PathProbe only reports statuses that mean "something
is here": `200` (OK), `301/302` (redirect), `401/403` (auth required), `500` (server error). This
turns thousands of requests into a short, actionable list.

## Analogy

Think of knocking on doors in a hallway. Most are silent (404). A few creak open (200), a few are
locked but clearly occupied (403), and a few point you down another hall (redirect). PathProbe
lists only the doors worth checking.

## Threading

`ThreadPoolExecutor` runs many requests at once, so 50 paths take about as long as one.
