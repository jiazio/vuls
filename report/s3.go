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

package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"

	c "github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
)

// CheckIfBucketExists check the existence of S3 bucket
func CheckIfBucketExists() error {
	svc := getS3()
	result, err := svc.ListBuckets(&s3.ListBucketsInput{})
	if err != nil {
		return fmt.Errorf(
			"Failed to list buckets. err: %s, profile: %s, region: %s",
			err, c.Conf.AwsProfile, c.Conf.AwsRegion)
	}

	found := false
	for _, bucket := range result.Buckets {
		if *bucket.Name == c.Conf.S3Bucket {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf(
			"Failed to find the buckets. profile: %s, region: %s, bukdet: %s",
			c.Conf.AwsProfile, c.Conf.AwsRegion, c.Conf.S3Bucket)
	}
	return nil
}

// S3Writer writes results to S3
type S3Writer struct {
	FormatXML       bool
	FormatPlainText bool
	FormatJSON      bool
}

func getS3() *s3.S3 {
	return s3.New(session.New(&aws.Config{
		Region:      aws.String(c.Conf.AwsRegion),
		Credentials: credentials.NewSharedCredentials("", c.Conf.AwsProfile),
	}))
}

// Write results to S3
// http://docs.aws.amazon.com/sdk-for-go/latest/v1/developerguide/common-examples.title.html
// TODO Refactoring
func (w S3Writer) Write(r models.ScanResult) (err error) {
	svc := getS3()

	timestr := r.ScannedAt.Format(time.RFC3339)
	var key string
	if len(r.Container.ContainerID) == 0 {
		key = fmt.Sprintf("%s/%s", timestr, r.ServerName)
	} else {
		key = fmt.Sprintf("%s/%s@%s", timestr, r.Container.Name, r.ServerName)
	}

	if w.FormatJSON {
		k := key + ".json"
		var b []byte
		if b, err = json.Marshal(r); err != nil {
			return fmt.Errorf("Failed to Marshal to JSON: %s", err)
		}
		_, err = svc.PutObject(&s3.PutObjectInput{
			Bucket: &c.Conf.S3Bucket,
			Key:    &k,
			Body:   bytes.NewReader(b),
		})
		if err != nil {
			return fmt.Errorf("Failed to upload data to %s/%s, %s", c.Conf.S3Bucket, key, err)
		}
	}

	if w.FormatPlainText {
		k := key + ".txt"
		text, err := toPlainText(r)
		if err != nil {
			return err
		}
		_, err = svc.PutObject(&s3.PutObjectInput{
			Bucket: &c.Conf.S3Bucket,
			Key:    &k,
			Body:   bytes.NewReader([]byte(text)),
		})
		if err != nil {
			return fmt.Errorf("Failed to upload data to %s/%s, %s", c.Conf.S3Bucket, key, err)
		}
	}

	if w.FormatXML {
		k := key + ".xml"
		var b []byte
		if b, err = xml.Marshal(r); err != nil {
			return fmt.Errorf("Failed to Marshal to XML: %s", err)
		}
		allBytes := bytes.Join([][]byte{[]byte(xml.Header + vulsOpenTag), b, []byte(vulsCloseTag)}, []byte{})
		_, err = svc.PutObject(&s3.PutObjectInput{
			Bucket: &c.Conf.S3Bucket,
			Key:    &k,
			Body:   bytes.NewReader(allBytes),
		})
		if err != nil {
			return fmt.Errorf("Failed to upload data to %s/%s, %s", c.Conf.S3Bucket, key, err)
		}
	}

	return nil
}
