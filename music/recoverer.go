/*
 * Stolen from my labstuff.
 */

package music

import (
       "fmt"
       "log"
)

// Recoverer is a wrapper that can be used around sensitive goroutines that may crash.
func Recoverer(name string, task func(), reporter func(interface{})) {

        defer func() {
                // log.Printf("This is the deferred func for service %s", name)
                if r := recover(); r != nil {
                        // log.Printf("This is the recover() for service %s. Calling reporter(). r: %v", name, r)
                        reporter(r)

                        // if err, ok := r.(error); ok {
                        //      log.Printf("Error in %s. Error: %v", name, err)
                        // } else {
                        //      log.Printf("Panic in %s. Panic: %v", name, err)
                        // }
                } else {
                        // r == nil indicates that this was just an error return, not a panic.
                        // log.Printf("Error in %s.", name)
                        // reporter(nil)
                }
        }()
        fmt.Printf("*** Recoverer about to start %s\n", name)
        task()
        log.Printf("*** Recoverer after running %s\n", name)
}
