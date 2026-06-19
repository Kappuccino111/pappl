//
// Scanner object for the Printer Application Framework
//
// Copyright © 2019-2026 by Michael R Sweet.
//
// Licensed under Apache License v2.0.  See the file "LICENSE" for more
// information.
//

#include "pappl-private.h"


//
// Local functions...
//

static int	compare_active_jobs(pappl_job_t *a, pappl_job_t *b);
static int	compare_all_jobs(pappl_job_t *a, pappl_job_t *b);
static int	compare_completed_jobs(pappl_job_t *a, pappl_job_t *b);


//
// 'papplScannerCancelAllJobs()' - Cancel all jobs on the scanner.
//
// This function cancels all jobs on the scanner.  If any job is currently being
// processed, it will be stopped at a convenient time so that the scanner will
// be left in a known state.
//

void
papplScannerCancelAllJobs(
    pappl_scanner_t *scanner)		// I - Scanner
{
  pappl_job_t	*job;			// Job information


  // Loop through all jobs and cancel them...
  _papplRWLockWrite(scanner);

  for (job = (pappl_job_t *)cupsArrayGetFirst(scanner->active_jobs); job; job = (pappl_job_t *)cupsArrayGetNext(scanner->active_jobs))
  {
    if (job->state == IPP_JSTATE_PROCESSING)
    {
      job->is_canceled = true;
    }
    else
    {
      job->state     = IPP_JSTATE_CANCELED;
      job->completed = time(NULL);

      cupsArrayRemove(scanner->active_jobs, job);
      cupsArrayAdd(scanner->completed_jobs, job);
    }
  }

  _papplRWUnlock(scanner);

  if (!scanner->system->clean_time)
    scanner->system->clean_time = time(NULL) + 60;
}


//
// 'papplScannerCreate()' - Create a new scanner.
//
// This function creates a new scanner (service) on the specified system.  The
// "scanner_id" argument specifies a positive integer identifier that is unique
// to the system.  If you specify a value of `0` a new identifier will be
// assigned.
//
// The "driver_name" argument specifies a named driver for the scanner, from
// the list of drivers registered with the @link papplSystemSetScannerDrivers@
// function.
//
// The "device_id" and "device_uri" arguments specify the IEEE-1284 device ID
// and device URI strings for the scanner.
//
// On error, this function sets the `errno` variable to one of the following
// values:
//
// - `EEXIST`: A scanner with the specified name already exists.
// - `EINVAL`: Bad values for the arguments were specified.
// - `EIO`: The driver callback failed.
// - `ENOENT`: No driver callback has been set.
// - `ENOMEM`: Ran out of memory.
//

pappl_scanner_t *			// O - Scanner or `NULL` on error
papplScannerCreate(
    pappl_system_t *system,		// I - System
    int            scanner_id,		// I - scanner-id value or `0` for new
    const char     *scanner_name,	// I - Human-readable scanner name
    const char     *driver_name,	// I - Driver name
    const char     *device_id,		// I - IEEE-1284 device ID
    const char     *device_uri)		// I - Device URI
{
  pappl_scanner_t	*scanner;	// Scanner
  char			resource[1024],	// Resource path
			*resptr,	// Pointer into resource path
			uuid[128];	// scanner-uuid
  pappl_sc_driver_data_t driver_data;	// Driver data
  ipp_t			*driver_attrs;	// Driver attributes


  // Range check input...
  if (!system || !scanner_name || !driver_name)
  {
    errno = EINVAL;
    return (NULL);
  }

  if (!device_uri)
  {
    errno = EINVAL;
    return (NULL);
  }

  if (!system->sc_driver_cb)
  {
    papplLog(system, PAPPL_LOGLEVEL_ERROR, "No scanner driver callback set, unable to add scanner.");
    errno = ENOENT;
    return (NULL);
  }

  // Prepare URI values for the scanner attributes...
  if (system->options & PAPPL_SOPTIONS_MULTI_QUEUE)
  {
    // Make sure scanner names that start with a digit have a resource path
    // containing an underscore...
    if (isdigit(*scanner_name & 255))
      snprintf(resource, sizeof(resource), "/ipp/scan/_%s", scanner_name);
    else
      snprintf(resource, sizeof(resource), "/ipp/scan/%s", scanner_name);

    // Convert URL reserved characters to underscore...
    for (resptr = resource + 10; *resptr; resptr ++)
    {
      if ((*resptr & 255) <= ' ' || strchr("\177/\\\'\"?#", *resptr))
	*resptr = '_';
    }

    // Eliminate duplicate and trailing underscores...
    resptr = resource + 10;
    while (*resptr)
    {
      if (resptr[0] == '_' && resptr[1] == '_')
        memmove(resptr, resptr + 1, strlen(resptr));
      else if (resptr[0] == '_' && !resptr[1])
        *resptr = '\0';
      else
        resptr ++;
    }
  }
  else
  {
    cupsCopyString(resource, "/ipp/scan", sizeof(resource));
  }

  // Make sure the scanner doesn't already exist...
  if (_papplSystemFindScanner(system, resource, 0, NULL))
  {
    papplLog(system, PAPPL_LOGLEVEL_ERROR, "Scanner '%s' already exists.", scanner_name);
    errno = EEXIST;
    return (NULL);
  }

  // Allocate memory for the scanner...
  if ((scanner = calloc(1, sizeof(pappl_scanner_t))) == NULL)
  {
    papplLog(system, PAPPL_LOGLEVEL_ERROR, "Unable to allocate memory for scanner: %s", strerror(errno));
    return (NULL);
  }

  papplLog(system, PAPPL_LOGLEVEL_INFO, "Scanner '%s' at resource path '%s'.", scanner_name, resource);

  _papplSystemMakeUUID(system, scanner_name, 0, uuid, sizeof(uuid));

  // Initialize scanner structure and attributes...
  cupsRWInit(&scanner->rwlock);

  scanner->system           = system;
  scanner->name             = strdup(scanner_name);
  scanner->dns_sd_name      = strdup(scanner_name);
  scanner->resource         = strdup(resource);
  scanner->resourcelen      = strlen(resource);
  scanner->uriname          = scanner->resource + 9;
					// Skip "/ipp/scan" in resource
  scanner->device_id        = device_id ? strdup(device_id) : NULL;
  scanner->device_uri       = device_uri ? strdup(device_uri) : NULL;
  scanner->driver_name      = strdup(driver_name);
  scanner->attrs            = ippNew();
  scanner->start_time       = time(NULL);
  scanner->config_time      = scanner->start_time;
  scanner->state            = IPP_PSTATE_IDLE;
  scanner->state_reasons    = PAPPL_PREASON_NONE;
  scanner->state_time       = scanner->start_time;
  scanner->uuid             = strdup(uuid);
  scanner->all_jobs         = cupsArrayNew((cups_array_cb_t)compare_all_jobs, NULL, NULL, 0, NULL, (cups_afree_cb_t)_papplJobDelete);
  scanner->active_jobs      = cupsArrayNew((cups_array_cb_t)compare_active_jobs, NULL, NULL, 0, NULL, NULL);
  scanner->completed_jobs   = cupsArrayNew((cups_array_cb_t)compare_completed_jobs, NULL, NULL, 0, NULL, NULL);
  scanner->next_job_id      = 1;
  scanner->max_active_jobs  = 1;
  scanner->max_completed_jobs = 100;

  // Verify all allocations succeeded...
  if (!scanner->name || !scanner->dns_sd_name || !scanner->resource || (device_id && !scanner->device_id) || (device_uri && !scanner->device_uri) || !scanner->driver_name || !scanner->attrs || !scanner->uuid)
  {
    _papplScannerDelete(scanner);
    return (NULL);
  }

  // Initialize driver and driver-specific attributes...
  driver_attrs = NULL;
  _papplScannerInitDriverData(&driver_data);

  if (!(system->sc_driver_cb)(system, driver_name, device_uri, device_id, &driver_data, &driver_attrs, system->sc_driver_cbdata))
  {
    errno = EIO;
    _papplScannerDelete(scanner);
    return (NULL);
  }

  if (!papplScannerSetDriverData(scanner, &driver_data, driver_attrs))
  {
    errno = EINVAL;
    _papplScannerDelete(scanner);
    return (NULL);
  }

  ippDelete(driver_attrs);

  // Add the scanner to the system...
  _papplSystemAddScanner(system, scanner, scanner_id);

  // scanner-id
  _papplRWLockWrite(scanner);
  ippAddInteger(scanner->attrs, IPP_TAG_PRINTER, IPP_TAG_INTEGER, "scanner-id", scanner->scanner_id);
  _papplRWUnlock(scanner);

  // Do any post-creation work...
  if (system->sc_create_cb)
    (system->sc_create_cb)(scanner, system->sc_driver_cbdata);

  _papplSystemConfigChanged(system);

  return (scanner);
}


//
// 'papplScannerDelete()' - Delete a scanner.
//
// This function deletes a scanner from a system, freeing all memory and
// canceling all jobs as needed.
//

void
papplScannerDelete(
    pappl_scanner_t *scanner)		// I - Scanner
{
  pappl_system_t *system = scanner->system;
					// System


  // Remove the scanner from the system object...
  _papplRWLockWrite(system);
  cupsArrayRemove(system->scanners, scanner);
  _papplRWUnlock(system);

  _papplScannerDelete(scanner);

  _papplSystemConfigChanged(system);
}


//
// '_papplScannerDelete()' - Free memory associated with a scanner.
//

void
_papplScannerDelete(
    pappl_scanner_t *scanner)		// I - Scanner
{
  // Mark as deleted...
  _papplRWLockWrite(scanner);
  scanner->is_deleted = true;
  _papplRWUnlock(scanner);

  // Unregister DNS-SD...
  _papplScannerUnregisterDNSSDNoLock(scanner);

  // If applicable, call the delete function...
  if (scanner->driver_data.delete_cb)
    (scanner->driver_data.delete_cb)(scanner, &scanner->driver_data);

  // Delete jobs...
  cupsArrayDelete(scanner->active_jobs);
  cupsArrayDelete(scanner->completed_jobs);
  cupsArrayDelete(scanner->all_jobs);

  // Free memory...
  free(scanner->name);
  free(scanner->dns_sd_name);
  free(scanner->location);
  free(scanner->geo_location);
  free(scanner->organization);
  free(scanner->org_unit);
  free(scanner->resource);
  free(scanner->device_id);
  free(scanner->device_uri);
  free(scanner->driver_name);
  free(scanner->scan_group);
  free(scanner->uuid);

  ippDelete(scanner->driver_attrs);
  ippDelete(scanner->attrs);

  cupsArrayDelete(scanner->links);

  cupsRWDestroy(&scanner->rwlock);

  free(scanner);
}


//
// '_papplScannerInitDriverData()' - Initialize scanner driver data to defaults.
//

void
_papplScannerInitDriverData(
    pappl_sc_driver_data_t *d)		// I - Driver data
{
  // Zero everything...
  memset(d, 0, sizeof(pappl_sc_driver_data_t));

  // Set default color mode...
  d->color_supported = PAPPL_SCAN_COLOR_MODE_RGB_24 | PAPPL_SCAN_COLOR_MODE_GRAYSCALE_8;
  d->color_default   = PAPPL_SCAN_COLOR_MODE_RGB_24;

  // Set default intents (all mandatory per eSCL spec)...
  d->intents_supported = PAPPL_SCAN_INTENT_DOCUMENT | PAPPL_SCAN_INTENT_PHOTO | PAPPL_SCAN_INTENT_PREVIEW | PAPPL_SCAN_INTENT_TEXT_AND_GRAPHIC;
  d->intent_default    = PAPPL_SCAN_INTENT_DOCUMENT;

  // Set default input source...
  d->input_sources_supported = PAPPL_SCAN_INPUT_SOURCE_PLATEN;
  d->input_source_default    = PAPPL_SCAN_INPUT_SOURCE_PLATEN;

  // Set default content type...
  d->content_supported = PAPPL_SCAN_CONTENT_AUTO;
  d->content_default   = PAPPL_SCAN_CONTENT_AUTO;

  // Set default resolution (300 DPI)...
  d->num_resolution    = 1;
  d->x_resolution[0]   = 300;
  d->y_resolution[0]   = 300;
  d->x_default         = 300;
  d->y_default         = 300;

  // Set default document formats (JPEG and PDF are mandatory per eSCL spec)...
  d->num_format = 2;
  cupsCopyString(d->format[0], "image/jpeg", sizeof(d->format[0]));
  cupsCopyString(d->format[1], "application/pdf", sizeof(d->format[1]));

  // Set default scan area to US Letter (8.5" x 11" in 1/300")...
  d->platen_min_width  = 1;
  d->platen_min_height = 1;
  d->platen_max_width  = 2550;		// 8.5 * 300
  d->platen_max_height = 3300;		// 11.0 * 300
}


//
// 'papplScannerSetDriverData()' - Set the driver data for a scanner.
//
// This function sets the driver data for a scanner, including all
// capabilities and defaults.  The caller is responsible for validating the
// data before calling this function.
//

bool					// O - `true` on success, `false` on failure
papplScannerSetDriverData(
    pappl_scanner_t        *scanner,	// I - Scanner
    pappl_sc_driver_data_t *data,	// I - Driver data
    ipp_t                  *attrs)	// I - Additional driver attributes or `NULL`
{
  // Range check input...
  if (!scanner || !data)
    return (false);

  // Validate required fields...
  if (!data->make_and_model[0] || !data->num_format || !data->num_resolution)
  {
    papplLog(scanner->system, PAPPL_LOGLEVEL_ERROR, "Scanner '%s': Invalid driver data (missing make/model, formats, or resolutions).", scanner->name);
    return (false);
  }

  // Copy the driver data...
  _papplRWLockWrite(scanner);

  scanner->driver_data = *data;

  // Replace driver attributes...
  ippDelete(scanner->driver_attrs);
  scanner->driver_attrs = attrs ? ippNew() : NULL;

  if (attrs)
    _papplCopyAttributes(scanner->driver_attrs, attrs, NULL, IPP_TAG_ZERO, false);

  scanner->config_time = time(NULL);

  _papplRWUnlock(scanner);

  return (true);
}


//
// 'papplScannerSetDriverDefaults()' - Set default values in the driver data.
//
// This function updates the defaults in the driver data for a scanner.
//

bool					// O - `true` on success, `false` on failure
papplScannerSetDriverDefaults(
    pappl_scanner_t        *scanner,	// I - Scanner
    pappl_sc_driver_data_t *data)	// I - Driver data with new defaults
{
  if (!scanner || !data)
    return (false);

  _papplRWLockWrite(scanner);

  // Update default values only...
  scanner->driver_data.color_default        = data->color_default;
  scanner->driver_data.intent_default       = data->intent_default;
  scanner->driver_data.input_source_default = data->input_source_default;
  scanner->driver_data.content_default      = data->content_default;
  scanner->driver_data.x_default            = data->x_default;
  scanner->driver_data.y_default            = data->y_default;

  scanner->config_time = time(NULL);

  _papplRWUnlock(scanner);

  _papplSystemConfigChanged(scanner->system);

  return (true);
}


//
// '_papplScannerUnregisterDNSSDNoLock()' - Unregister DNS-SD services.
//
// This is a stub for PR 1; real DNS-SD registration is in PR 8.
//

void
_papplScannerUnregisterDNSSDNoLock(
    pappl_scanner_t *scanner)		// I - Scanner
{
  if (scanner->dns_sd_services)
  {
    cupsDNSSDServiceDelete(scanner->dns_sd_services);
    scanner->dns_sd_services = NULL;
  }
}


//
// 'compare_active_jobs()' - Compare two active jobs.
//

static int				// O - Result of comparison
compare_active_jobs(pappl_job_t *a,	// I - First job
                    pappl_job_t *b)	// I - Second job
{
  return (b->job_id - a->job_id);
}


//
// 'compare_all_jobs()' - Compare two jobs.
//

static int				// O - Result of comparison
compare_all_jobs(pappl_job_t *a,	// I - First job
                 pappl_job_t *b)	// I - Second job
{
  return (b->job_id - a->job_id);
}


//
// 'compare_completed_jobs()' - Compare two completed jobs.
//

static int				// O - Result of comparison
compare_completed_jobs(pappl_job_t *a,	// I - First job
                       pappl_job_t *b)	// I - Second job
{
  return (b->job_id - a->job_id);
}
