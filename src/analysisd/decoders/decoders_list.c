/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "decoder.h"
#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"
#include "analysisd.h"

static OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi, char** error_str);

/* Create the Event List */
void OS_CreateOSDecoderList()
{
    os_analysisd_decoderlist_pn = NULL;
    os_analysisd_decoderlist_nopn = NULL;

    return;
}

/* Get first osdecoder */
OSDecoderNode *OS_GetFirstOSDecoder(const char *p_name)
{
    /* If program name is set, we return the forpname list */
    if (p_name) {
        return (os_analysisd_decoderlist_pn);
    }

    return (os_analysisd_decoderlist_nopn);
}

/* Add an osdecoder to the list */
static OSDecoderNode *_OS_AddOSDecoder(OSDecoderNode *s_node, OSDecoderInfo *pi, char** error_str)
{
    OSDecoderNode *tmp_node = s_node;
    OSDecoderNode *new_node;
    int rm_f = 0;

    if (tmp_node) {
        os_calloc(1, sizeof(OSDecoderNode), new_node);

        /* Going to the last node */
        do {
            /* Check for common names */
            if ((strcmp(tmp_node->osdecoder->name, pi->name) == 0) &&
                    (pi->parent != NULL)) {
                if ((tmp_node->osdecoder->prematch ||
                        tmp_node->osdecoder->regex) && pi->regex_offset) {
                    rm_f = 1;
                }

                /* Multi-regexes patterns cannot have prematch */
                if (pi->prematch) {
                    str_error_append(error_str, PDUP_INV, pi->name);
                    goto error;
                }

                /* Multi-regex patterns cannot have fts set */
                if (pi->fts) {
                    str_error_append(error_str, PDUPFTS_INV, pi->name);
                    goto error;
                }

                if ((tmp_node->osdecoder->regex || tmp_node->osdecoder->plugindecoder) && (pi->regex || pi->plugindecoder)) {
                    tmp_node->osdecoder->get_next = 1;
                } else {
                    str_error_append(error_str, DUP_INV, pi->name);
                    goto error;
                }
            }

        } while (tmp_node->next && (tmp_node = tmp_node->next));

        /* Must have a prematch set */
        if (!rm_f && (pi->regex_offset & AFTER_PREVREGEX)) {
            str_error_append(error_str, INV_OFFSET, pi->name);
            goto error;
        }

        tmp_node->next = new_node;

        new_node->next = NULL;
        new_node->osdecoder = pi;
        new_node->child = NULL;
    }

    else {
        /* Must not have a previous regex set */
        if (pi->regex_offset & AFTER_PREVREGEX) {
            str_error_append(error_str, INV_OFFSET, pi->name);
            return (NULL);
        }

        os_calloc(1, sizeof(OSDecoderNode), tmp_node);

        tmp_node->child = NULL;
        tmp_node->next = NULL;
        tmp_node->osdecoder = pi;

        s_node = tmp_node;
    }

    return (s_node);

error:
    os_free(new_node);

    return (NULL);
}

int OS_AddOSDecoder(OSDecoderInfo *pi, OSDecoderNode **pn_osdecodernode, OSDecoderNode **npn_osdecodernode, char** error_str)
{
    int added = 0;
    OSDecoderNode *osdecodernode;

    /* We can actually have two lists. One with program
     * name and the other without.
     */
    if (pi->program_name) {
        osdecodernode = *pn_osdecodernode;
    } else {
        osdecodernode = *npn_osdecodernode;
    }

    /* Search for parent on both lists */
    if (pi->parent) {
        OSDecoderNode *tmp_node = *pn_osdecodernode;

        /* List with p_name */
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                tmp_node->child = _OS_AddOSDecoder(tmp_node->child, pi, error_str);
                if (!tmp_node->child) {
                    str_error_append(error_str, DEC_PLUGIN_ERR);
                    return (0);
                }
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* List without p name */
        tmp_node = *npn_osdecodernode;
        while (tmp_node) {
            if (strcmp(tmp_node->osdecoder->name, pi->parent) == 0) {
                tmp_node->child = _OS_AddOSDecoder(tmp_node->child, pi, error_str);
                if (!tmp_node->child) {
                    str_error_append(error_str, DEC_PLUGIN_ERR);
                    return (0);
                }
                added = 1;
            }
            tmp_node = tmp_node->next;
        }

        /* OSDecoder was added correctly */
        if (added == 1) {
            return (1);
        }

        str_error_append(error_str, PPLUGIN_INV, pi->parent);
        return (0);
    } else {
        osdecodernode = _OS_AddOSDecoder(osdecodernode, pi, error_str);
        if (!osdecodernode) {
            str_error_append(error_str, DEC_PLUGIN_ERR);
            return (0);
        }

        /* Update global decoder pointers */
        if (pi->program_name) {
            *pn_osdecodernode = osdecodernode;
        } else {
            *npn_osdecodernode = osdecodernode;
        }
    }
    return (1);
}
