#ifndef _GUI_ZCASH_H
#define _GUI_ZCASH_H
#include "rust.h"
#include "gui.h"

#ifdef CYPHERPUNK_VERSION
NetworkType GetZcashNetworkType(void);
#endif
void GuiSetZcashUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetZcashGUIData(void);
PtrT_TransactionCheckResult GuiGetZcashCheckResult(void);
UREncodeResult *GuiGetZcashSignQrCodeData(void);
void FreeZcashMemory(void);

void GuiZcashOverview(lv_obj_t *parent, void *totalData);

#endif
