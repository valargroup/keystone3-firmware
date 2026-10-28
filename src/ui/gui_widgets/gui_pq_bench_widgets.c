#include "gui.h"
#include "gui_views.h"
#include "gui_page.h"
#include "gui_pq_bench_widgets.h"
#include "pq_bench.h"

// The screen shows the median time per operation; the UART log has min/max and sizes.

#ifdef FEATURE_PQ_BENCH

#define PQ_BENCH_POLL_MS        500

static PageWidget_t *g_pageWidget;
static lv_obj_t *g_resultLabel;
static lv_obj_t *g_runButton;
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

static void ShowResults(void)
{
    const PqBenchResult_t *results;
    uint32_t count = PqBenchGetResults(&results);
    char text[768] = "scheme  keygen / sign / verify\n";
    size_t used = strlen(text);

    for (uint32_t i = 0; i < count && used < sizeof(text); i++) {
        const char *name = pq_bench_scheme_name(results[i].scheme);
        if (results[i].status != PQ_BENCH_OK) {
            used += snprintf(text + used, sizeof(text) - used, "%s  error %d\n", name, (int)results[i].status);
            continue;
        }
        char keygen[16], sign[16], verify[16];
        FormatDuration(keygen, sizeof(keygen), results[i].report.keygen.median_ns);
        FormatDuration(sign, sizeof(sign), results[i].report.sign.median_ns);
        FormatDuration(verify, sizeof(verify), results[i].report.verify.median_ns);
        used += snprintf(text + used, sizeof(text) - used, "%s (n=%lu)\n  %s / %s / %s\n", name,
                         (unsigned long)results[i].report.iterations, keygen, sign, verify);
    }
    lv_label_set_text(g_resultLabel, text);
}

static void PollTimerHandler(lv_timer_t *timer)
{
    if (PqBenchGetState() == PQ_BENCH_RUNNING) {
        return;
    }
    lv_timer_del(timer);
    g_pollTimer = NULL;
    ShowResults();
    lv_obj_clear_state(g_runButton, LV_STATE_DISABLED);
}

static void RunHandler(lv_event_t *e)
{
    lv_label_set_text(g_resultLabel, "Running all schemes...\nSLH-128s and SLH-256s can take minutes.");
    lv_obj_add_state(g_runButton, LV_STATE_DISABLED);
    if (!PqBenchStart(PQ_BENCH_ALL_SCHEMES, 0)) {
        lv_label_set_text(g_resultLabel, "Could not start; see the UART log.");
        lv_obj_clear_state(g_runButton, LV_STATE_DISABLED);
        return;
    }
    if (g_pollTimer == NULL) {
        g_pollTimer = lv_timer_create(PollTimerHandler, PQ_BENCH_POLL_MS, NULL);
    }
}

void GuiPqBenchWidgetsInit(void)
{
    g_pageWidget = CreatePageWidget();
    lv_obj_t *cont = g_pageWidget->contentZone;

    g_resultLabel = GuiCreateIllustrateLabel(cont, "Times hash-based signatures on this device.\n"
                                             "Results are medians; the UART log has min/max.");
    lv_obj_set_width(g_resultLabel, 432);
    lv_obj_align(g_resultLabel, LV_ALIGN_TOP_LEFT, 24, 12);

    g_runButton = GuiCreateBtn(cont, "Run");
    lv_obj_align(g_runButton, LV_ALIGN_BOTTOM_RIGHT, -36, -24);
    lv_obj_add_event_cb(g_runButton, RunHandler, LV_EVENT_CLICKED, NULL);

    if (PqBenchGetState() == PQ_BENCH_DONE) {
        ShowResults();
    } else if (PqBenchGetState() == PQ_BENCH_RUNNING) {
        lv_obj_add_state(g_runButton, LV_STATE_DISABLED);
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
