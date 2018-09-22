#include <stdlib.h>
#include <new>

#include "modsecurity/intervention.h"

namespace modsecurity {

/**
 * @name    msc_new_intervention
 * @brief   allocate a new ModSecurityIntervention
 *

 * For languages that need to access interventions via ffi. So no need to put it
 * in a header file.

 *
 * @returns a pointer to a clean ModSecurityIntervention,
 * or NULL if the allocation failed.
 *
 */
extern "C" ModSecurityIntervention * msc_new_intervention() {
	try {
		ModSecurityIntervention * rv = new ModSecurityIntervention();
		// It's actually just a struct, so initialize it to zero values,
		// although status is set to 200 ¯\_(ツ)_/¯
		modsecurity::intervention::clean(rv);
		return rv;
	}
	catch (const std::bad_alloc&) {
		return NULL;
	}
}

/**
 * @name    msc_free_intervention
 * @brief   free a ModSecurityIntervention pointer
 *
 * For languages that need to access interventions via ffi. So no need to put it
 * in a header file.
 *
 */
extern "C" void msc_free_intervention(ModSecurityIntervention *it) {
	// free the url and log pointers if they're assigned
	modsecurity::intervention::free(it);
	delete it;
}

} // namespace modsecurity
