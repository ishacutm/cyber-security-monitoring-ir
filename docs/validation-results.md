# Validation results

Validated on 2026-09-26 in a Linux build environment with Python 3.12.14, Flask 3.1.3 and pytest 9.1.1. The project targets Python 3.11+; Windows instructions are included, but a Windows runtime was not available for execution testing.

- Dependencies installed successfully.
- Application launched using python app.py on 127.0.0.1:5000 with debug disabled.
- SQLite initialized automatically with 34 events, 12 alerts and six incidents. Reinitialization did not duplicate seed data.
- Automated suite: 46 tests passed.
- Browser validation: Chromium 134 through Playwright, desktop 1512x1050 and mobile 390x844.
- All major navigation routes returned successful pages.
- Four Chart.js charts rendered from local data.
- All ten simulator buttons generated the expected local records.
- Alert acknowledgement, incident creation and the five sequential response actions completed through the browser.
- Metric tests verified exact known MTTD/MTTA/MTTC/MTTR values and N/A for incomplete recovery.
- CSV download succeeded and its content was inspected.
- Log search and pagination worked in the browser.
- No JavaScript page errors or external browser requests were observed.
- Mobile dashboard had no page-level horizontal overflow; data tables scroll within their containers.
- Screenshots show the actual running application.

Automated tests also cover CSRF rejection, non-ASCII invalid tokens, missing routes, SQL-like search text, HTML escaping, formula-safe CSV cells, malformed filters, invalid transitions, duplicate suppression, time-window boundaries, source/user separation, and generic database/server error pages.

These checks validate an educational local application, not production security effectiveness or standards compliance.
