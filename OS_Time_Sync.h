#ifndef OS_TIME_SYNC_H
#define OS_TIME_SYNC_H
#include <stdbool.h>
#include <time.h>
typedef struct timespec Time_Type;

typedef enum {
    OSTS_Request        = 0u    /* Request Sync, sent by slaver */
    ,OSTS_Sync          = 1u    /* Sync, sent by master */
    ,OSTS_Follow_Up     = 2u    /* Follow_Up, sent by master */
    ,OSTS_Delay_Req     = 3u    /* Delay_Req, sent by slaver */
    ,OSTS_Delay_Resp    = 4u    /* Delay_Resp, sent by master */
} OSTS_TransmitType;

typedef struct OSTS_Sync_Ptp_Time_Buffer_ 
{
    Time_Type     t_1;
    Time_Type     t_2;
    Time_Type     t_3;
    Time_Type     t_4;
    Time_Type     Delay;
    Time_Type     Offset;
    bool          is_sync;
} OSTS_Sync_Ptp_Time_Buffer;

static OSTS_Sync_Ptp_Time_Buffer ptp_time_buffer; 

void OSTS_Request(void);

void OSTS_Sync(void); 

void OSTS_Follow_Up(void);

void OSTS_Delay_Req(void); 

void OSTS_Delay_Resp(void);

void OSTS_Delay_Resp(void);

void OSTS_GetGlobelTime(Time_Type* GlobelTime);

void OSTS_GetLocalTime(Time_Type* LocalTime);
#endif //OS_TIME_SYNC_H