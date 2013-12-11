/*
 * Copyright (c) 2010-2014 David Muller <roxon@users.sourceforge.net>.
 * All rights reserved. Use of the code is allowed under the
 * Artistic License 2.0 terms, as specified in the LICENSE file
 * distributed with this code, or available from
 * http://www.opensource.org/licenses/artistic-license-2.0.php
 */
package org.pwsafe.passwordsafeswt.model.comparator;

import org.pwsafe.lib.datastore.PwsEntryBean;

/**
 * @author timmydog
 */
public class TitleSubStringMatcher implements FindMatcher {
	public boolean matches(final String searchString, final PwsEntryBean entry) {

		return entry.getTitle().toLowerCase().contains(searchString.toLowerCase());
	}
}
