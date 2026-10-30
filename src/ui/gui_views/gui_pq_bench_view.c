#include "gui_obj.h"
#include "gui_views.h"
#include "gui_pq_bench_widgets.h"

int32_t GuiPqBenchViewEventProcess(void *self, uint16_t usEvent, void *param, uint16_t usLen)
{
    GUI_ASSERT(g_pqBenchView.isActive);

    switch (usEvent) {
    case GUI_EVENT_OBJ_INIT:
        GuiPqBenchWidgetsInit();
        break;
    case GUI_EVENT_OBJ_DEINIT:
        GuiPqBenchWidgetsDeInit();
        break;
    case GUI_EVENT_REFRESH:
        GuiPqBenchWidgetsRefresh();
        break;
    default:
        return ERR_GUI_UNHANDLED;
    }
    return SUCCESS_CODE;
}

GUI_VIEW g_pqBenchView = {
    .id = SCREEN_PQ_BENCH,
    .previous = NULL,
    .isActive = false,
    .optimization = false,
    .pEvtHandler = GuiPqBenchViewEventProcess,
};
