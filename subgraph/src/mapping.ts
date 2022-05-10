import { BigInt } from "@graphprotocol/graph-ts"
import {
  Cert,
  caAuthEvent,
  caRegisterEvent,
  downloadEvent,
  issueEvent,
  requestUpdateEvent,
  requestUploadEvent,
  revokeEvent,
  updateEvent,
  uploadEvent
} from "../generated/Cert/Cert"
import { ExampleEntity } from "../generated/schema"

export function handleissueEvent(event: issueEvent): void {
  // Entities can be loaded from the store using a string ID; this ID
  // needs to be unique across all entities of the same type
  let caEntity = caCertEntity.load(event.params.from.toHexString());
  if (!caEntity) {
    caEntity = new caCertEntity(event.params.from.toHexString())
  }
  let certs = event.params.certid;
  for (let v in certs) {
    caEntity.certId.push(v);
    caEntity.save()
  }

  let users = event.params.receiver;
  for (let i = 0; i < users.length; i++) {
    let userEntity = userCertEntity.load(users[i].toHexString());
    if (!userCertEntity) {
      userEntity = new userCertEntity(users[i].toHexString());
    }
    userEntity.certId.push(certs[i].toHexString());
    let stateEntity = certStateEntity.load(certs[i].toHexString());
    if (!stateEntity) {
      stateEntity = new certStateEntity(certs[i].toHexString());
    }
    stateEntity.state = 'issued';
    userEntity.save();
    stateEntity.save();
  }
}

export function handlerevokeEvent(event: revokeEvent): void {
  let entity = certStateEntity.load(event.params.certid.toHexString());
  if (!entity) return;
  entity.state = 'revoked';
  entity.save();
}

export function handleuploadEvent(event: uploadEvent): void {
  let entity = certStateEntity.load(event.params.certid.toHexString());
  if (!entity) return;
  entity.state = 'uploaded';
  entity.save();
}

export function handlerequestUploadEvent(event: requestUploadEvent): void {
  let entity = requestUploadEntity.load(event.params.certid.toHexString());
  if (!entity) return;
  entity.owner = event.params.owner.toHexString();
  entity.save
}

export function handlecaAuthEvent(event: caAuthEvent): void {
  let entity = caPublicKeyEntity.load(event.params.ca.toHexString())
  if (!entity) {
    entity = new caPublicKeyEntity(event.params.ca.toHexString());
  }
  entity.pk = event.params.pk;
  entity.save();
}
