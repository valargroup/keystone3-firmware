#ifndef _GUI_ETH_H
#define _GUI_ETH_H

#include "rust.h"
#include "lvgl.h"

void GuiSetEthUrData(URParseResult *urResult, URParseMultiResult *urMultiResult, bool multi);
void *GuiGetEthData(void);
PtrT_TransactionCheckResult GuiGetEthCheckResult(void);
void GuiEthTxOverview(lv_obj_t *parent, void *totalData);
void GuiEthTxDetails(lv_obj_t *parent, void *totalData);

UREncodeResult *GuiGetEthSignQrCodeData(void);
UREncodeResult *GuiGetEthSignUrDataUnlimited(void);
void GetEthTypeDomainPos(uint16_t *x, uint16_t *y, void *param);
void GetEthMessagePos(uint16_t *x, uint16_t *y, void *param);
bool GetEthTypeDataHashExist(void *indata, void *param);
bool GetEthContractFromInternal(char *address, char *inputData);
bool GetEthTypeDataChainExist(void *indata, void *param);
bool GetEthTypeDataVersionExist(void *indata, void *param);
bool GetEthContractFromExternal(char *address, char *selectorId, uint64_t chainId, char *inputData);
void GetEthGetSignerAddress(void *indata, void *param, uint32_t maxLen);
void GetEthTypeDomainSize(uint16_t *width, uint16_t *height, void *param);
bool GetEthMessageFromExist(void *indata, void *param);
bool GetEthMessageFromNotExist(void *indata, void *param);
bool GetEthPermitWarningExist(void *indata, void *param);
bool GetEthPermitCantSign(void *indata, void *param);
bool GetEthOperationWarningExist(void *indata, void *param);
void *GuiGetEthPersonalMessage(void);
void GetEthPersonalMessageType(void *indata, void *param, uint32_t maxLen);
void GetMessageFrom(void *indata, void *param, uint32_t maxLen);
void GetMessageUtf8(void *indata, void *param, uint32_t maxLen);
void GetMessageRaw(void *indata, void *param, uint32_t maxLen);
void GuiShowEthMessagePaged(lv_obj_t *parent, void *param, bool raw);
void EthContractCheckRawDataCallback(void);

void *GuiGetEthTypeData(void);
void GetEthTypedDataDomianName(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataDomainHash(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataMessageHash(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataSafeTxHash(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataDomianVersion(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataDomianChainId(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataDomianVerifyContract(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataDomianSalt(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataPrimayType(void *indata, void *param, uint32_t maxLen);
void GetEthTypedDataMessage(void *indata, void *param, uint32_t maxLen);
int GetEthTypedDataMessageLen(void *param);
void GetEthTypedDataFrom(void *indata, void *param, uint32_t maxLen);

typedef struct {
    uint64_t chainId;
    char *name;
    char *symbol;
} EvmNetwork_t;

typedef struct {
    char *symbol;
    char *contract_address;
    uint8_t decimals;
} Erc20Contract_t;

typedef struct {
    char *recipient;
    char *value;
} Erc20Transfer_t;

EvmNetwork_t FindEvmNetwork(uint64_t chainId);
void *FindErc20Contract(char *contract_address);


void FreeEthMemory(void);

#endif
