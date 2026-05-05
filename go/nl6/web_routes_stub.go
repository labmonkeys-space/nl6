/*
 * © 2025 Labmonkeys Space
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

//go:build !linux

// Non-Linux stubs for Linux-specific route-script generation helpers.
// The full implementations live in web_routes_linux.go (auto-excluded on non-Linux).
package main

func generateDebianRouteSection(_ map[string]bool) string  { return "" }
func generateRHELRouteSection(_ map[string]bool) string    { return "" }
func generateSUSERouteSection(_ map[string]bool) string    { return "" }
