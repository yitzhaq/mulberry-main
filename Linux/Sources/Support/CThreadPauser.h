/*
    Copyright (c) 2007 Cyrus Daboo. All rights reserved.
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
    
        http://www.apache.org/licenses/LICENSE-2.0
    
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

#ifndef __CTHREADPAUSER__MULBERRY__
#define __CTHREADPAUSER__MULBERRY__

#include <ace/Thread_Mutex.h>
#include <ace/Condition_Thread_Mutex.h>
#include <ace/Guard_T.h>

class CThreadPauser
{
 public:
	CThreadPauser() :
#if defined(ACE_HAS_THREADS)
		cond_(mutex_),
#endif
		paused_(false){ }
	~CThreadPauser() {}
	void pause()
		{
#if defined(ACE_HAS_THREADS)
			mutex_.acquire();
			do { paused_ = true; cond_.wait(); }while(paused_);
			mutex_.release();
#endif
		}
	void unpause()
		{
#if defined(ACE_HAS_THREADS)
			mutex_.acquire();
			paused_ = false;
			cond_.broadcast();
			mutex_.release();
#endif
		}
	bool paused() const {
#if defined(ACE_HAS_THREADS)
		ACE_Guard<ACE_Thread_Mutex> guard_(mutex_);
#endif
		return paused_;
	}
 private:
#if defined(ACE_HAS_THREADS)
	mutable ACE_Thread_Mutex mutex_;
	ACE_Condition_Thread_Mutex cond_;
#endif
	bool paused_;
};

#endif
