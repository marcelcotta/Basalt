/*
 Copyright (c) 2025 Basalt contributors. All rights reserved.

 Governed by the TrueCrypt License 3.0 the full text of which is contained in
 the file License.txt included in TrueCrypt binary and source code distribution
 packages.

 Portable getopt_long implementation for Windows/MSVC.
 Provides POSIX-compatible getopt, getopt_long, and getopt_long_only.
*/

#ifndef TC_CLI_GETOPT_H
#define TC_CLI_GETOPT_H

#ifdef TC_WINDOWS

#ifdef __cplusplus
extern "C" {
#endif

#define no_argument        0
#define required_argument  1
#define optional_argument  2

struct option
{
	const char *name;
	int         has_arg;
	int        *flag;
	int         val;
};

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

static char *_tc_optarg = NULL;
static int   _tc_optind = 1;
static int   _tc_opterr = 1;
static int   _tc_optopt = '?';

/* Bind external names to static storage */
#ifndef TC_GETOPT_IMPL
char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = '?';
#endif

static int getopt (int argc, char *const argv[], const char *optstring)
{
	static int sp = 1;
	int c;
	const char *cp;

	if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
		return -1;

	if (argv[optind][0] == '-' && argv[optind][1] == '-' && argv[optind][2] == '\0')
	{
		optind++;
		return -1;
	}

	c = argv[optind][sp];
	optopt = c;

	cp = strchr (optstring, c);
	if (cp == NULL || c == ':')
	{
		if (opterr)
			fprintf (stderr, "%s: unknown option '-%c'\n", argv[0], c);

		if (argv[optind][++sp] == '\0')
		{
			optind++;
			sp = 1;
		}
		return '?';
	}

	if (*(cp + 1) == ':')
	{
		if (argv[optind][sp + 1] != '\0')
		{
			optarg = &argv[optind][sp + 1];
		}
		else if (++optind >= argc)
		{
			if (opterr)
				fprintf (stderr, "%s: option '-%c' requires an argument\n", argv[0], c);
			sp = 1;
			return (optstring[0] == ':') ? ':' : '?';
		}
		else
		{
			optarg = argv[optind];
		}
		optind++;
		sp = 1;
	}
	else
	{
		if (argv[optind][++sp] == '\0')
		{
			optind++;
			sp = 1;
		}
		optarg = NULL;
	}

	return c;
}

static int getopt_long (int argc, char *const argv[], const char *optstring,
	const struct option *longopts, int *longindex)
{
	int i;
	size_t len;
	const char *arg;

	if (optind >= argc)
		return -1;

	arg = argv[optind];

	/* Not an option */
	if (arg[0] != '-')
		return -1;

	/* Short option */
	if (arg[1] != '-')
		return getopt (argc, argv, optstring);

	/* "--" end marker */
	if (arg[2] == '\0')
	{
		optind++;
		return -1;
	}

	/* Long option: skip "--" */
	arg += 2;

	for (i = 0; longopts[i].name != NULL; i++)
	{
		len = strlen (longopts[i].name);

		if (strncmp (arg, longopts[i].name, len) != 0)
			continue;

		/* Exact match or match with '=' */
		if (arg[len] != '\0' && arg[len] != '=')
			continue;

		if (longindex)
			*longindex = i;

		optind++;

		if (longopts[i].has_arg == required_argument || longopts[i].has_arg == optional_argument)
		{
			if (arg[len] == '=')
			{
				optarg = (char *) &arg[len + 1];
			}
			else if (longopts[i].has_arg == required_argument)
			{
				if (optind >= argc)
				{
					if (opterr)
						fprintf (stderr, "%s: option '--%s' requires an argument\n",
							argv[0], longopts[i].name);
					return '?';
				}
				optarg = argv[optind++];
			}
			else
			{
				optarg = NULL;
			}
		}
		else
		{
			optarg = NULL;
		}

		if (longopts[i].flag != NULL)
		{
			*longopts[i].flag = longopts[i].val;
			return 0;
		}

		return longopts[i].val;
	}

	if (opterr)
		fprintf (stderr, "%s: unknown option '--%s'\n", argv[0], arg);

	optind++;
	return '?';
}

static int getopt_long_only (int argc, char *const argv[], const char *optstring,
	const struct option *longopts, int *longindex)
{
	/* Simplified: just forward to getopt_long */
	return getopt_long (argc, argv, optstring, longopts, longindex);
}

#ifdef __cplusplus
}
#endif

#endif /* TC_WINDOWS */
#endif /* TC_CLI_GETOPT_H */
