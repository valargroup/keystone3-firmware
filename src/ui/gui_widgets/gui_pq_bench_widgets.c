#include "gui.h"
#include "gui_views.h"
#include "gui_page.h"
#include "gui_pq_bench_widgets.h"
#include "pq_bench.h"

// One row per scheme, each with its own Run button, so schemes run one at a time. Rows show
// median times from the flash record; the UART log has min/max and sizes.

#ifdef FEATURE_PQ_BENCH

#define PQ_BENCH_POLL_MS        500
#define PQ_BENCH_HEADER_HEIGHT  96
#define PQ_BENCH_ROW_HEIGHT     112

static PageWidget_t *g_pageWidget;
static lv_obj_t *g_statusLabel;
static lv_obj_t *g_rowLabels[PQ_BENCH_MAX_SCHEMES];
static lv_obj_t *g_runButtons[PQ_BENCH_MAX_SCHEMES];
static lv_timer_t *g_pollTimer;

static void FormatDuration(char *out, size_t outLen, uint64_t ns)
{
    uint64_t us = ns / 1000;
    if (us < 1000) {
        snprintf(out, outLen, "%luus", (unsigned long)us);
    } else if (us < 1000000) {
        snprintf(out, outLen, "%lu.%lums", (unsigned long)(us / 1000), (unsigned long)(us % 1000 / 100));
    } else {
        snprintf(out, outLen, "%lu.%02lus", (unsigned long)(us / 1000000), (unsigned long)(us % 1000000 / 10000));
    }
}

// The line under scheme `scheme`'s name: its latest times, the step running now, or the step
// during which the device reset.
static void FormatRow(char *out, size_t outLen, const PqBenchRecord_t *record, uint32_t scheme, bool running)
{
    if (record != NULL && record->running && record->scheme == scheme) {
        const char *what = running ? "Running" : "CRASHED: reset during";
        if (record->iterations > 1) {
            snprintf(out, outLen, "%s %s, iteration %lu of %lu%s", what, PqBenchStepName(record->step),
                     (unsigned long)record->iteration + 1, (unsigned long)record->iterations, running ? "..." : "");
        } else {
            snprintf(out, outLen, "%s %s%s", what, PqBenchStepName(record->step), running ? "..." : "");
        }
        return;
    }
    if (record == NULL || !(record->finished & (1UL << scheme))) {
        snprintf(out, outLen, "Not run yet");
        return;
    }
    const PqBenchResult_t *result = &record->results[scheme];
    if (result->status != PQ_BENCH_OK) {
        snprintf(out, outLen, "Error %d", (int)result->status);
        return;
    }
    char keygen[16], sign[16], verify[16];
    FormatDuration(keygen, sizeof(keygen), result->report.keygen.median_ns);
    FormatDuration(sign, sizeof(sign), result->report.sign.median_ns);
    FormatDuration(verify, sizeof(verify), result->report.verify.median_ns);
    if (result->report.iterations > 1) {
        snprintf(out, outLen, "keygen %s, sign %s, verify %s (median of %lu)", keygen, sign, verify,
                 (unsigned long)result->report.iterations);
    } else {
        snprintf(out, outLen, "keygen %s, sign %s, verify %s", keygen, sign, verify);
    }
}

static void UpdateRows(void)
{
    const PqBenchRecord_t *record = PqBenchGetRecord();
    bool running = PqBenchGetState() == PQ_BENCH_RUNNING;
    char text[96];

    if (running) {
        lv_label_set_text(g_statusLabel, "Running; the other buttons wait until it finishes.");
    } else if (record != NULL && record->running) {
        lv_label_set_text_fmt(g_statusLabel, "CRASHED: the device reset while running %s.",
                              pq_bench_scheme_name(record->scheme));
    } else {
        lv_label_set_text(g_statusLabel, "Run each scheme on its own; each Run does one\n"
                          "key generation, signature and verification.");
    }
    for (uint32_t i = 0; i < pq_bench_scheme_count() && i < PQ_BENCH_MAX_SCHEMES; i++) {
        FormatRow(text, sizeof(text), record, i, running);
        lv_label_set_text(g_rowLabels[i], text);
        if (running) {
            lv_obj_add_state(g_runButtons[i], LV_STATE_DISABLED);
        } else {
            lv_obj_clear_state(g_runButtons[i], LV_STATE_DISABLED);
        }
    }
}

static void PollTimerHandler(lv_timer_t *timer)
{
    UpdateRows();
    if (PqBenchGetState() != PQ_BENCH_RUNNING) {
        lv_timer_del(timer);
        g_pollTimer = NULL;
    }
}

static void RunHandler(lv_event_t *e)
{
    int32_t scheme = (int32_t)(intptr_t)lv_event_get_user_data(e);

    if (!PqBenchStart(scheme, 0)) {
        lv_label_set_text_fmt(g_statusLabel, "Could not start: %s", PqBenchGetError());
        return;
    }
    UpdateRows();
    if (g_pollTimer == NULL) {
        g_pollTimer = lv_timer_create(PollTimerHandler, PQ_BENCH_POLL_MS, NULL);
    }
}

void GuiPqBenchWidgetsInit(void)
{
    g_pageWidget = CreatePageWidget();
    lv_obj_t *cont = g_pageWidget->contentZone;
    lv_obj_add_flag(cont, LV_OBJ_FLAG_SCROLLABLE);

    g_statusLabel = GuiCreateIllustrateLabel(cont, "");
    lv_obj_set_width(g_statusLabel, 432);
    lv_obj_align(g_statusLabel, LV_ALIGN_TOP_LEFT, 24, 12);

    for (uint32_t i = 0; i < pq_bench_scheme_count() && i < PQ_BENCH_MAX_SCHEMES; i++) {
        lv_coord_t y = PQ_BENCH_HEADER_HEIGHT + i * PQ_BENCH_ROW_HEIGHT;
        lv_obj_t *name = GuiCreateTextLabel(cont, pq_bench_scheme_name(i));
        lv_obj_align(name, LV_ALIGN_TOP_LEFT, 24, y);

        g_rowLabels[i] = GuiCreateIllustrateLabel(cont, "");
        lv_obj_set_width(g_rowLabels[i], 312);
        lv_obj_align(g_rowLabels[i], LV_ALIGN_TOP_LEFT, 24, y + 40);

        g_runButtons[i] = GuiCreateBtn(cont, "Run");
        lv_obj_align(g_runButtons[i], LV_ALIGN_TOP_RIGHT, -24, y + 8);
        lv_obj_add_event_cb(g_runButtons[i], RunHandler, LV_EVENT_CLICKED, (void *)(intptr_t)i);
    }

    UpdateRows();
    if (PqBenchGetState() == PQ_BENCH_RUNNING) {
        g_pollTimer = lv_timer_create(PollTimerHandler, PQ_BENCH_POLL_MS, NULL);
    }
}

void GuiPqBenchWidgetsDeInit(void)
{
    if (g_pollTimer != NULL) {
        lv_timer_del(g_pollTimer);
        g_pollTimer = NULL;
    }
    if (g_pageWidget != NULL) {
        DestroyPageWidget(g_pageWidget);
        g_pageWidget = NULL;
    }
}

void GuiPqBenchWidgetsRefresh(void)
{
    SetNavBarLeftBtn(g_pageWidget->navBarWidget, NVS_BAR_RETURN, CloseCurrentViewHandler, NULL);
    SetMidBtnLabel(g_pageWidget->navBarWidget, NVS_BAR_MID_LABEL, "PQ Bench");
}

#else

void GuiPqBenchWidgetsInit(void) {}
void GuiPqBenchWidgetsDeInit(void) {}
void GuiPqBenchWidgetsRefresh(void) {}

#endif
