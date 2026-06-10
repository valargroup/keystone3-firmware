#ifndef _GUI_ZCASH_H
#define _GUI_ZCASH_H
#include "rust.h"
#include "gui.h"

void GuiSetZcashUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetZcashGUIData(void);
void GuiZcashOverviewWithData(lv_obj_t *parent, DisplayPczt *data);
void GuiZcashOverviewWithDataAndHeight(lv_obj_t *parent, DisplayPczt *data, lv_coord_t height);
void GuiZcashOverview(lv_obj_t *parent, void *totalData);
PtrT_TransactionCheckResult GuiGetZcashCheckResult(void);
UREncodeResult *GuiGetZcashSignQrCodeData(void);
UREncodeResult *GuiGetZcashSignUrDataUnlimited(void);
void FreeZcashMemory(void);


#endif
