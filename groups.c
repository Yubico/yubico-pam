#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <grp.h>

#include "util.h"
#include "groups.h"

#define ERR(X) D(X);
#define WARN(X) if (verbose) { D(x); }
#define INFO(x) if (verbose) { D(x); }


#define DEFAULT_SUPLEMENTARY_GROUPS (15)

#ifdef _SC_NGROUPS_MAX
int get_max_groups()
{
	const long max = sysconf(_SC_NGROUPS_MAX);
	if (max <= INT_MAX)
		return (int)max;
	return INT_MAX;
}
#else
int get_max_groups()
{
	return NGROUPS_MAX;
}
#endif

#ifndef HAVE_GROUP_MEMBER
static int group_member(const gid_t gid)
{
	const int max = getgroups(0, NULL);
	int found = 0;

	if (max < 0)
	{
		ERR(("Can not get current groups quantity: %s", strerror(errno)));
		goto out;
	}

	if (0 == max)
		goto out;

	gid_t *groups = malloc(sizeof(gid_t)*max);
	if (groups == NULL)
	{
		ERR(("Can not allocate memory for groups: %s", strerror(errno)));
		goto out;
	}

	const int num = getgroups(max, groups);
	if (num < 0)
	{
		ERR(("Can not get current groups list: %s", strerror(errno)));
		goto out;
	}

	for (int i =0; i < num; ++i)
	{
		if (gid == groups[i])
		{
			found = 1;
			break;
		}
	}

out:
	if (NULL != groups)
		free(groups);
	return found;
}
#endif

int set_supplementary_groups(const char *const username, const gid_t gid, const int verbose)
{
	// set supplementary groups for user
	// 	[in] username
	// 	[in] gid mandatory group for user (it will be not setted)
	//	Return value
	//		0  - OK
	//		-1 - Error
	INFO(("set_supplementary_groups %s/%d", username, gid));

	gid_t *groups = NULL;
	int max_groups = DEFAULT_SUPLEMENTARY_GROUPS, num_groups = 0;
	const int total_groups = get_max_groups();

	do
	{
		groups = malloc(sizeof(gid_t)*max_groups);
		if (groups == NULL)
		{
			ERR(("Can not allocate memory for supplementary groups: %s", strerror(errno)));
			return -1;
		}

		int cur_groups = max_groups;
		if (0 <= getgrouplist(username, gid, groups, &cur_groups))
		{
			num_groups = cur_groups;
		}
		else
		{
			max_groups *= 2;
			max_groups = (max_groups<cur_groups)?cur_groups:max_groups;
			free(groups);
		}
	} while (max_groups < total_groups && 0 == num_groups);

	if (num_groups > 0)
	{
		INFO(("groups = %d", num_groups));
		{
			initgroups(username, gid);
			int new_groups = 0;
			for (int ind = 0; ind < num_groups; ++ind)
			{
				if (0 == group_member(groups[ind])) //Need to attach
					groups[new_groups++] = groups[ind];
			}
			num_groups = new_groups;
		}

		INFO(("need update groups = %d", num_groups));

		if (num_groups >0 && 0 > setgroups(num_groups, groups))
		{
			ERR(("Can not set supplementary groups: %s", strerror(errno)));
            num_groups = -1;
		}
	}
	else if (num_groups < 0)
	{
		ERR(("Can not get groups for user %s", username));
	}

	free(groups);
	return (num_groups >= 0)?0:-1;
}
