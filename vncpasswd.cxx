/* Copyright (C) 2002-2003 RealVNC Ltd.  All Rights Reserved.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <rfb/vncAuth.h>
#include <rfb/util.h>

// BeOS specific include files.
#include <Directory.h>
#include <FindDirectory.h>
#include <Path.h>

// Hack for BeOS, add a getpass function.  AGMS.
// $Header: /CommonBe/agmsmith/Programming/VNC/vnc-4.0-beossrc/beosserver/RCS/vncpasswd.cxx,v 1.3 2005/05/29 23:01:21 agmsmith Exp $

char *getpass (const char *Prompt)
{
  int         i;
  static char Password [128];

  fprintf (stderr, "%s", Prompt);
  fflush (stderr);
  memset (Password, 0, sizeof (Password));
  fgets (Password, sizeof (Password), stdin);
  i = strlen (Password);
  if (i > 0 && Password[i-1] == '\n')
    Password[i-1] = 0; // Remove trailing line feed.
  return Password;
}


static const char * GetDefaultPasswordFilePath (void)
{
  static char DefaultPath [1024];
  int         ErrorCode;
  BPath       Path;

  // BeOS Specific code for finding a standard directory for our settings.

  strcpy (DefaultPath, "/boot/home/.vnc/passwd");
  ErrorCode = find_directory (B_USER_SETTINGS_DIRECTORY, &Path);
  if (ErrorCode != B_OK)
    return DefaultPath;
  Path.Append ("VNCServer/passwd");
  if (strlen (Path.Path()) >= sizeof (DefaultPath))
    return DefaultPath;
  strcpy (DefaultPath, Path.Path());
  return DefaultPath;
}

using namespace rfb;

char* prog;

static void usage()
{
  fprintf(stderr,"usage: %s [-pPassword] [file]\n",prog);
  exit(1);
}

int main(int argc, char** argv)
{
  prog = argv[0];

  const char* fname = 0;
  char* passwordString = 0;
  char  storageString [9]; // Max password length is 8 characters.

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-q") == 0) { // allowed for backwards compatibility
    } else if (argv[i][0] == '-' && argv[i][1] == 'p') {
      memset (storageString, 0, sizeof (storageString));
      strncpy (storageString, argv[i] + 2, sizeof (storageString));
      storageString [sizeof (storageString) - 1] = 0;
      passwordString = storageString;
    } else if (argv[i][0] == '-') {
      usage();
    } else if (!fname) {
      fname = argv[i];
    } else {
      usage();
    }
  }

  if (!fname) {
    fname = GetDefaultPasswordFilePath ();
    // Also make sure that the parent directory exists, create if needed.
    BPath Path (fname);
    Path.GetParent (&Path);
    create_directory (Path.Path(), 0755);
  }

  if (passwordString == 0)
  {
    // Get the password from the command line user.
    while (true) {
      char* passwd;
      passwd = getpass("Password: ");
      if (!passwd) {
        perror("getpass error");
        exit(1);
      }
      if (strlen(passwd) < 6) {
        if (strlen(passwd) == 0) {
          fprintf(stderr,"Password not changed\n");
          exit(1);
        }
        fprintf(stderr,"Password must be at least 6 characters - try again\n");
        continue;
      }

      if (strlen(passwd) > 8) {
        passwd[8] = '\0';
        fprintf(stderr,"Note that the password has been truncated down to the maximum 8 characters\n");
      }

      CharArray passwdCopy(strDup(passwd));

      passwd = getpass("Verify: ");
      if (!passwd) {
        perror("getpass error");
        exit(1);
      }
      if (strlen(passwd) > 8)
        passwd[8] = '\0';

      if (strcmp(passwdCopy.buf, passwd) != 0) {
        fprintf(stderr,"Passwords don't match - try again\n");
        continue;
      }
      passwordString = passwd;
      break;
    }
  }

  if (strlen (passwordString) < 6)
  {
    fprintf(stderr,"Password must be at least 6 characters.\n");
    exit (1);
  }

  FILE* fp = fopen(fname,"w");
  if (!fp) {
    fprintf(stderr,"Couldn't open %s for writing\n",fname);
    exit(1);
  }
  chmod(fname, S_IRUSR|S_IWUSR);

  vncAuthObfuscatePasswd(passwordString);

  if (fwrite(passwordString, 8, 1, fp) != 1) {
    fprintf(stderr,"Writing to %s failed\n",fname);
    exit(1);
  }

  fclose(fp);

  return 0;
}
