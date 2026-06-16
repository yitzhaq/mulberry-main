// Copyright ©2005, 2006 Freescale Semiconductor, Inc.
// Please see the License for the specific language governing rights and
// limitations under the License.
// ===========================================================================
//	VPLPopupButton.cpp				©1997 Metrowerks Inc. All rights reserved.
// ===========================================================================

#include "VPLPopupButton.h"


LPane*
VPLPopupButton::CreateFromStream(
	LStream		*inStream)
{
	return new LPopupButton(inStream);
}