#!/usr/bin/env bash
# Create the device certificate and attach it to the thing and policy.
#
# Run once, after the stack is deployed. Certificates are created here rather
# than in CloudFormation because a private key must never appear in a template
# or in version control - AWS returns it exactly once, at creation.
set -euo pipefail

REGION="${REGION:-ca-central-1}"
DEVICE="${DEVICE:-securehealth-fridge-01}"
CERTS="${CERTS:-./certs}"

mkdir -p "$CERTS"

if [ -f "$CERTS/device-certificate.pem.crt" ]; then
  echo "Certificate already exists in $CERTS - delete it first to re-provision."
  exit 1
fi

echo "Creating device certificate..."
ARN=$(aws iot create-keys-and-certificate \
  --set-as-active \
  --certificate-pem-outfile "$CERTS/device-certificate.pem.crt" \
  --private-key-outfile "$CERTS/device-private.pem.key" \
  --public-key-outfile "$CERTS/device-public.pem.key" \
  --region "$REGION" \
  --query certificateArn --output text)

echo "Attaching policy ${DEVICE}-policy..."
aws iot attach-policy --policy-name "${DEVICE}-policy" \
  --target "$ARN" --region "$REGION"

echo "Attaching certificate to thing ${DEVICE}..."
aws iot attach-thing-principal --thing-name "$DEVICE" \
  --principal "$ARN" --region "$REGION"

echo "Downloading Amazon root CA..."
curl -s -o "$CERTS/AmazonRootCA1.pem" https://www.amazontrust.com/repository/AmazonRootCA1.pem

echo
echo "Done. Certificate ARN:"
echo "  $ARN"
echo
echo "Data endpoint:"
aws iot describe-endpoint --endpoint-type iot:Data-ATS --region "$REGION" --query endpointAddress --output text
echo
echo "Keep $CERTS out of version control. To revoke this device later:"
echo "  aws iot update-certificate --certificate-id <id> --new-status REVOKED --region $REGION"
