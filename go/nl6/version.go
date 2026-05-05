/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

// Version is the simulator's self-reported build identity. It is
// populated at link time via `-ldflags "-X main.Version=<value>"`.
// Resolution precedence (driven by the Makefile):
//
//  1. APP_VERSION environment variable (CI tag-build override)
//  2. `git describe --tags` — tagged commit → `vX.Y.Z`; HEAD ahead of
//     the last tag → `vX.Y.Z-N-g<sha>` so ahead-of-tag dev builds
//     never masquerade as the tag itself
//  3. the literal string "dev" (fallback for shallow / untagged clones)
//
// A binary built by `go build` directly (bypassing `make build`)
// carries the zero-value "dev" — an obvious signal that ldflags
// injection did not run.
var Version = "dev"
