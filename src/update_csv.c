#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

#include "trace.h"
#include "utils.h"

/* TODO: check aio_write to replace fwrite */

void rotate_location_file(ThreadData* td, time_t now)
{
    char *filename = "./output/location.csv";
    char closedFilename[64];

    if (!td->is_first_thread)
        return;

    td->csv.location_creation_time = now;
    if (td->csv.location_file_p)
    {
        if (fclose(td->csv.location_file_p) != 0)
        {
            LOG(LOG_ERR, "Failed to close location file during rotation. Error: %s\n",
                    strerror(errno));
        }
        else
        {
            sprintf(closedFilename, "./output/location/location_%lu.csv", (unsigned long)now);
            if(rename(filename, closedFilename) != 0)
            {
                LOG(LOG_ERR, "Failed to move location file during rotation. Error: %s\n",
                        strerror(errno));
            }
            else
            {
                LOG(LOG_DBG, "Closed file during location file %s rotation\n",
                    closedFilename);
            }
        }
    }
    td->csv.location_file_p = fopen(filename, "w");
    if (td->csv.location_file_p == NULL)
    {
        LOG(LOG_ERR, "Failed to close location file during rotation. Error: %s\n",
                strerror(errno));
    }
    else
    {
        LOG(LOG_INFO, "Location file %s rotation\n", filename);
    }
}

void rotate_host_file(ThreadData* td, time_t now)
{
    //char *filename = "./output/host.csv";
    char filename[64];
    char closedFilename[64];
    td->csv.host_creation_time = now;
    sprintf(filename,"./output/T_%03d/host.csv",td->t_index);
    if (td->csv.host_file_p)
    {
        if (fclose(td->csv.host_file_p) != 0)
        {
            LOG(LOG_ERR, "Failed to close host file during rotation. Error: %s\n",
                    strerror(errno));
        }
        else
        {
            sprintf(closedFilename, "./output/T_%03d/host/host_%lu.csv", td->t_index, (unsigned long)now);
            if(rename(filename, closedFilename) != 0)
            {
                LOG(LOG_ERR, "Failed to move host file during rotation. Error: %s\n",
                        strerror(errno));
            }
            else
            {
                LOG(LOG_DBG, "Closed file during host file %s rotation\n",
                    closedFilename);
            }
        }
    }
    td->csv.host_file_p = fopen(filename, "w");
    if (td->csv.host_file_p == NULL)
    {
        LOG(LOG_ERR, "Failed to close host file during rotation. Error: %s\n",
                strerror(errno));
    }
    else
    {
        LOG(LOG_INFO, "Host file %s rotation\n", filename);
    }
}

void rotate_url_file(ThreadData* td, time_t now)
{
    //char *filename = "./output/url.csv";
    char filename[64];
    char closedFilename[64];
    td->csv.url_creation_time = now;
    sprintf(filename,"./output/T_%03d/url.csv",td->t_index);
    if (td->csv.url_file_p)
    {
        if (fclose(td->csv.url_file_p) != 0)
        {
            LOG(LOG_ERR, "Failed to close URL file during rotation. Error: %s\n",
                    strerror(errno));
        }
        else
        {
            sprintf(closedFilename, "./output/T_%03d/url/url_%lu.csv",td->t_index,(unsigned long)now);
            if(rename(filename, closedFilename) != 0)
            {
                LOG(LOG_ERR, "Failed to move url file during rotation. Error: %s\n",
                        strerror(errno));
            }
            else
            {
                LOG(LOG_DBG, "Closed file during url file %s rotation\n",
                    closedFilename);
            }
        }
    }
    td->csv.url_file_p = fopen(filename, "w");
    if (td->csv.url_file_p == NULL)
    {
        LOG(LOG_ERR, "Failed to close URL file during rotation. Error: %s\n",
                strerror(errno));
    }
    else
    {
        LOG(LOG_INFO, "URL file %s rotation\n", filename);
    }
}

void init_csv(ThreadData* td)
{
    time_t now = time(NULL);
    {
        struct stat st;
        char folder_name[64];

        sprintf(folder_name,"./output/T_%03d",td->t_index);
        if (stat(folder_name,&st))
            mkdir(folder_name,0777);

        sprintf(folder_name,"./output/T_%03d/host",td->t_index);
        if (stat(folder_name,&st))
            mkdir(folder_name,0777);

        sprintf(folder_name,"./output/T_%03d/url",td->t_index);
        if (stat(folder_name,&st))
            mkdir(folder_name,0777);

        if (td->is_first_thread)
        {
            sprintf(folder_name,"./output/location");
            if (stat(folder_name,&st))
                mkdir(folder_name,0777);
        }
    }

    rotate_location_file(td,now);
    rotate_host_file(td,now);
    rotate_url_file(td,now);
}

void close_csv(ThreadData* td)
{
    if (td->csv.location_file_p)
    {
        fclose(td->csv.location_file_p);
        td->csv.location_file_p = NULL;
    }
    if (td->csv.host_file_p)
    {
        fclose(td->csv.host_file_p);
        td->csv.host_file_p = NULL;
    }
    if (td->csv.url_file_p)
    {
        fclose(td->csv.url_file_p);
        td->csv.url_file_p = NULL;
    }
}

void write_location_csv(ThreadData* td, const char* name, int location)
{
    if (!td->is_first_thread)
        return;

    if (td->csv.location_file_p)
    {
        time_t now = time(NULL);
        if (now - td->csv.location_creation_time > cfg.period)
        {
            rotate_location_file(td,now);
        }
        else
        {
            int result;
            result = fprintf(td->csv.location_file_p, "%s,%d,%lu\n", name, location, (unsigned long)now);
            /* TODO: error handling */
        }
    }
    else
    {

        /* TODO: error handling */
    }
}

void write_host_csv(ThreadData* td, const char* name, const char* host)
{
    if (td->csv.host_file_p)
    {
        time_t now = time(NULL);
        if (now - td->csv.host_creation_time > cfg.period)
        {
            rotate_host_file(td,now);
        }
        else
        {
            int result;
            result = fprintf(td->csv.host_file_p, "%s,%s,%lu\n", name, host, (unsigned long)now);
            /* TODO: error handling */
        }
    }
    else
    {

        /* TODO: error handling */
    }
}

void write_url_csv(ThreadData* td, const char* name, const char* url, const char* host)
{
    if (td->csv.url_file_p)
    {
        time_t now = time(NULL);
        if (now - td->csv.url_creation_time > cfg.period)
        {
            rotate_url_file(td, now);
        }
        else
        {
            int result;
            result = fprintf(td->csv.url_file_p, "%s,%s%s,%lu\n", name, host, url, (unsigned long)now);
            /* TODO: error handling */
        }
    }
    else
    {

        /* TODO: error handling */
    }
}

