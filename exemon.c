/* exemon */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <pwd.h>

#include <libaudit.h>
#include <auparse.h>

int auparse_exhaustive_find_field(auparse_state_t *auparse, const char *field);
void auparse_dump_records(auparse_state_t *auparse, FILE *fp);

int auparse_exhaustive_find_field(auparse_state_t *auparse, const char *field) {
	const char *status;

	auparse_first_record(auparse);
	auparse_first_field(auparse);

	status = auparse_find_field(auparse, field);
	while (!status && auparse_next_record(auparse)) {
		status = auparse_find_field(auparse, field); 
	}

	return (status ? 1 : 0);
}

void auparse_dump_records(auparse_state_t *auparse, FILE *fp) {
	auparse_first_record(auparse);
	if (!fp) fp = stdout;

	fprintf(fp, "%s\n", auparse_get_record_text(auparse));
	while (auparse_next_record(auparse)) {
		fprintf(fp, "%s\n", auparse_get_record_text(auparse));
	}
}

int main(int argc, char **argv) {
	/* we're probably going to be started by auditd so, you know, whatever */
	/* set up stdin to be searched ruthlessly */

	FILE *log;
	auparse_state_t *auparse;
	uint32_t syscall;
	int auid, uid;
	int wtf;
	uint32_t _argc, i; 
	const char *exe, *path, *success;
	char *cmdline, *tmp_cmd; 
	char _argv[8];
	struct passwd *au, *u;
	char *real_user, *apparent_user; 

	_argc = 0;
	cmdline = NULL;

	log = fopen("/tmp/exemon.log", "w");

/*	auparse = auparse_init(AUSOURCE_LOGS, NULL); */
	auparse = auparse_init(AUSOURCE_FILE_POINTER, stdin); 

	if (!auparse) {
		fprintf(log, "Couldn't do the thing with the thing.\n");
		exit(1);
	}

	while ((wtf = auparse_next_event(auparse)) > 0) {
		/* Start fresh */
		auid = -1;
		uid = -1;
		exe = NULL;
		path = NULL;
		success = NULL;
		_argc = 0;
		if (cmdline) free(cmdline);
		cmdline = NULL;

		/* Now we're doing the thing */
/*		auparse_first_field(auparse); */
/*		auparse_first_record(auparse); */
		auparse_first_field(auparse);
		if (auparse_find_field(auparse, "syscall")) {
			syscall = auparse_get_field_int(auparse);
			if (syscall == 59 || syscall == 11) {
				if (auparse_exhaustive_find_field(auparse, "auid")) {
					auid = auparse_get_field_int(auparse);
					au = getpwuid(auid);
					if (au) real_user = strdup(au->pw_name);
					else asprintf(&real_user, "UID_%i", auid);
					au = NULL;
				}

				if (auparse_exhaustive_find_field(auparse, "uid")) {
					uid = auparse_get_field_int(auparse);
					u = getpwuid(uid);
					if (u) apparent_user = strdup(u->pw_name);
					else asprintf(&apparent_user, "UID_%i", uid);
					u = NULL;
				}

				if (auparse_exhaustive_find_field(auparse, "success"))
					success = auparse_get_field_str(auparse);

				if (auparse_exhaustive_find_field(auparse, "exe"))
					exe = auparse_get_field_str(auparse);

				if (auparse_exhaustive_find_field(auparse, "argc")) {
					_argc = auparse_get_field_int(auparse);
					for (i = 0; i < _argc; i++) {
						snprintf(_argv, 8, "a%i", i);
						if (auparse_find_field(auparse, _argv)) {
							if (!cmdline) asprintf(&cmdline, "%s", auparse_interpret_field(auparse));
							else {
								asprintf(&tmp_cmd, "%s %s", cmdline, auparse_interpret_field(auparse));
								free(cmdline); /* avoid leaking cmdline */
								cmdline = tmp_cmd;
							}
						}
					}
				}

				if (auparse_exhaustive_find_field(auparse, "cwd"))
					path = auparse_get_field_str(auparse);
				else path = strdup("(unknown)");

				if (exe && uid >= 0 && path && success) {
					if (auid == uid || auid == -1) {
						if (cmdline && (success[0] == 'y' || success[0] == 'Y')) {
							fprintf(log, "%s ran %s in path %s with args: %s\n", apparent_user, exe, path, cmdline);
						} else {
							fprintf(log, "%s failed to run %s in path %s\n", apparent_user, exe, path); 
							if (!cmdline) { fprintf(log, "note: no cmdline: record: \n"); auparse_dump_records(auparse, log); }
						}
					} else {
						if (cmdline && (success[0] == 'y' || success[0] == 'Y')) {
							fprintf(log, "%s (as %s) ran %s in path %s with args: %s\n", real_user, apparent_user, exe, path, cmdline);
						} else {
							fprintf(log, "%s (as %s) failed to run %s in path %s\n", real_user, apparent_user, exe, path);
						}
					}
				} else {
					fprintf(log, "Incomplete record? path = %x, success = %x, uid = %i, exe = %x\n", path, success, uid, exe);
					fprintf(log, "record:\n");
					auparse_dump_records(auparse, log);
				}
				fflush(log);

				/* avoid leaking on usernames and unknown paths */
				free(apparent_user);
				free(real_user);
				if (path[0] == '(') { free(path); path = NULL; }
				apparent_user = NULL;
				real_user = NULL;
			}
		}
	}

	fprintf(log, "destroyed\n");
	fclose(log); 

	auparse_destroy(auparse);

	return 0;
}

