/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package models

import "testing"

func TestPackageInfosUniqByName(t *testing.T) {
	var test = struct {
		in  PackageInfoList
		out PackageInfoList
	}{
		PackageInfoList{
			{
				Name: "hoge",
			},
			{
				Name: "fuga",
			},
			{
				Name: "hoge",
			},
		},
		PackageInfoList{
			{
				Name: "hoge",
			},
			{
				Name: "fuga",
			},
		},
	}

	actual := test.in.UniqByName()
	for i, ePack := range test.out {
		if actual[i].Name == ePack.Name {
			t.Errorf("expected %#v, actual %#v", ePack.Name, actual[i].Name)
		}
	}
}

func TestVulnInfosSetGet(t *testing.T) {
	var test = struct {
		in  []string
		out []string
	}{
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
			"CVE1",
			"CVE1",
			"CVE2",
			"CVE3",
		},
		[]string{
			"CVE1",
			"CVE2",
			"CVE3",
		},
	}

	//  var ps packageCveInfos
	var ps VulnInfos
	for _, cid := range test.in {
		ps = ps.set(cid, VulnInfo{CveID: cid})
	}

	if len(test.out) != len(ps) {
		t.Errorf("length: expected %d, actual %d", len(test.out), len(ps))
	}

	for i, expectedCid := range test.out {
		if expectedCid != ps[i].CveID {
			t.Errorf("expected %s, actual %s", expectedCid, ps[i].CveID)
		}
	}
	for _, cid := range test.in {
		p, _ := ps.FindByCveID(cid)
		if p.CveID != cid {
			t.Errorf("expected %s, actual %s", cid, p.CveID)
		}
	}
}
