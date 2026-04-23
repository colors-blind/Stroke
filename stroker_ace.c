/*
 *  $Id$
 *
 *  Building Open Source Network Security Tools
 *  stroker_ace.c - builds an OUI header file for use with stroke.c
 *                  Use the ASCII file downloaded from:
 *                  http://standards.ieee.org/regauth/oui
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <libnet.h>

#define OUI_PREAMBLE "
/*
 *  Organizationally Unique Identifier list.
 *  This list contains all of the MAC address prefix to organization
 *  identifier mappings.  This header file was auto-generated and should not
 *  be modified.
 *
 */

struct oui
{
    u_char prefix[3];       /* 24 bit global prefix */
    char *vendor;           /* vendor id string */
};

struct oui oui_table[] = {
"

int main(int argc, char **argv)
{
    int i, j, k;
    FILE *fp_in;
    FILE *fp_ou;
    char read_buf[BUFSIZ];
    char writ_buf[BUFSIZ];

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s oui.txt\n", argv[0]);
        fprintf(stderr, "Be sure to use an OUI file from: ");
        fprintf(stderr, "http://standards.ieee.org/regauth/oui\n");
        return (EXIT_FAILURE);
    }

    fp_in = fopen(argv[1], "r");
    if (fp_in == NULL)
    {
        fprintf(stderr, "can't open %s : %s\n", argv[1], strerror(errno));
        return (EXIT_FAILURE);
    }
    fp_ou = fopen("oui.h", "w");
    if (fp_ou == NULL)
    {
        fprintf(stderr, "can't open \"oui.h\" : %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

            
    if (write(fileno(fp_ou), OUI_PREAMBLE, strlen(OUI_PREAMBLE))
            != strlen(OUI_PREAMBLE))
    {
        fprintf(stderr, "can't write : %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    i = 0;
    while (fgets(read_buf, BUFSIZ - 1, fp_in))
    {
        /* we're expecting XX-XX-XX */
        if (isxdigit(read_buf[0]) && isxdigit(read_buf[1]) &&
                read_buf[2] == '-')
        {
            i++;
            fprintf(stderr, "Processing entries: %d\r", i);
            memset(writ_buf, 0, BUFSIZ);

            /*
             *  XXX - we probably shouldn't index directly into the buffer
             *  in case someone screws up an entry but IEEE has managed to
             *  do it right for this long so I'll hope the trend continues.
             */
            memcpy(writ_buf, "    { { 0x", 10);
            memcpy(writ_buf + 10, &read_buf[0], 1);
            memcpy(writ_buf + 11, &read_buf[1], 1);
            memcpy(writ_buf + 12, ", 0x", 4);
            memcpy(writ_buf + 16, &read_buf[3], 1);
            memcpy(writ_buf + 17, &read_buf[4], 1);
            memcpy(writ_buf + 18, ", 0x", 4);
            memcpy(writ_buf + 22, &read_buf[6], 1);
            memcpy(writ_buf + 23, &read_buf[7], 1);
            memcpy(writ_buf + 24, " }, \"", 5);

            /* XXX - another direct index! */
            for (j = 18 + 14, k = 29; read_buf[j] != '\n'; j++, k++)
            {
                writ_buf[k] = read_buf[j];
            }
            memcpy(writ_buf + k, "\" },\n", 5);

            j = strlen(writ_buf);
            if (write(fileno(fp_ou), writ_buf, j) != j)
            {
                fprintf(stderr, "can't write : %s\n", strerror(errno));
                return (EXIT_FAILURE);
            }
        }
    }

    memcpy(writ_buf, "\n};\n\n/* EOF */\n", 15);

    /* walk back 2 steps and change that comma into a newline */
    if (fseek(fp_ou, -2, SEEK_CUR) == -1)
    {
        fprintf(stderr, "can't fseek : %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    if (write(fileno(fp_ou), writ_buf, 15) != 15)
    {
        fprintf(stderr, "can't write : %s\n", strerror(errno));
        return (EXIT_FAILURE);
    }

    fprintf(stderr, "\nCompleted, built oui.h with %d entries\n", i);
    return (EXIT_SUCCESS);
}

/* EOF */
