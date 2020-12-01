#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <time.h>


#ifdef XLINK_DBG_PHASE  
extern int DebugLevel;
#define DEBUG_OFF    0
#define DEBUG_ERROR    1
#define DEBUG_WARN    2
#define DEBUG_TRACE    3
#define DEBUG_INFO    4
#define DBGPRINT(Level, fmt, args...)   \
{                                       \
    if (Level <= DebugLevel)          \
    {                                   \
        printf("[%s() - %d]", __FUNCTION__, __LINE__);    \
        printf( fmt, ## args);          \
    }                                   \
}
#else
#include "cs_log.h"
#define DEBUG_OFF    LOG_LEVEL_DEBUG
#define DEBUG_ERROR    LOG_LEVEL_ERR
#define DEBUG_WARN    LOG_LEVEL_DEBUG
#define DEBUG_TRACE    LOG_LEVEL_DEBUG
#define DEBUG_INFO    LOG_LEVEL_DEBUG

#define DBGPRINT(Level,args...) log_log(Level, __FUNCTION__, __LINE__, args);
#endif

#endif
