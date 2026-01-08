// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: MIT

/*
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Intersight API Response Types
export interface IntersightResponse<T> {
  Results?: T[];
  Count?: number;
}

// Policy Types
export interface PolicyBase {
  Name: string;
  Description?: string;
  Tags?: Tag[];
  Organization?: MoReference;
}

export interface BootPolicy extends PolicyBase {
  ObjectType: 'boot.PrecisionPolicy';
  BootDevices?: BootDevice[];
  ConfiguredBootMode?: string;
  EnforceUefiSecureBoot?: boolean;
}

export interface BiosPolicy extends PolicyBase {
  ObjectType: 'bios.Policy';
  // BIOS tokens
}

export interface NetworkPolicy extends PolicyBase {
  ObjectType: 'vnic.LanConnectivityPolicy';
  TargetPlatform?: string;
  PlacementMode?: string;
}

export interface StoragePolicy extends PolicyBase {
  ObjectType: 'storage.StoragePolicy';
}

// Pool Types
export interface PoolBase {
  Name: string;
  Description?: string;
  Tags?: Tag[];
  Organization?: MoReference;
  Size?: number;
  Assigned?: number;
}

export interface IpPool extends PoolBase {
  ObjectType: 'ippool.Pool';
  IpV4Blocks?: IpV4Block[];
  IpV4Config?: IpV4Config;
}

export interface MacPool extends PoolBase {
  ObjectType: 'macpool.Pool';
  MacBlocks?: MacBlock[];
}

export interface UuidPool extends PoolBase {
  ObjectType: 'uuidpool.Pool';
  Prefix?: string;
  UuidSuffixBlocks?: UuidBlock[];
}

export interface WwnnPool extends PoolBase {
  ObjectType: 'fcpool.Pool';
  PoolPurpose?: 'WWNN';
  IdBlocks?: WwnnBlock[];
}

export interface WwpnPool extends PoolBase {
  ObjectType: 'fcpool.Pool';
  PoolPurpose?: 'WWPN';
  IdBlocks?: WwpnBlock[];
}

// Profile Types
export interface ServerProfile {
  Name: string;
  Description?: string;
  TargetPlatform?: string;
  Action?: string;
  Tags?: Tag[];
  Organization?: MoReference;
  
  // Policy Associations
  BootPolicySettings?: PolicyReference;
  BiosPolicy?: MoReference;
  StoragePolicy?: MoReference;
  LanConnectivityPolicy?: MoReference;
  SanConnectivityPolicy?: MoReference;
  IpmiOverLanPolicy?: MoReference;
  VirtualMediaPolicy?: MoReference;
  
  // Pool Associations
  UuidAddressType?: string;
  UuidPool?: MoReference;
  
  // Server Assignment
  AssignedServer?: MoReference;
  ServerAssignmentMode?: string;
}

// Supporting Types
export interface Tag {
  Key: string;
  Value: string;
}

export interface MoReference {
  ClassId: string;
  ObjectType: string;
  Moid: string;
}

export interface PolicyReference extends MoReference {
  PolicyQualifierType?: string;
}

export interface BootDevice {
  ClassId: string;
  ObjectType: string;
  Name: string;
  Enabled?: boolean;
}

export interface IpV4Block {
  From: string;
  To?: string;
  Size?: number;
}

export interface IpV4Config {
  Gateway: string;
  Netmask: string;
  PrimaryDns?: string;
  SecondaryDns?: string;
}

export interface MacBlock {
  From: string;
  To?: string;
  Size?: number;
}

export interface UuidBlock {
  From: string;
  To?: string;
  Size?: number;
}

export interface WwnnBlock {
  From: string;
  To?: string;
  Size?: number;
}

export interface WwpnBlock {
  From: string;
  To?: string;
  Size?: number;
}

// Inventory Types
export interface ComputeServer {
  Moid: string;
  Name: string;
  Model: string;
  Serial: string;
  OperPowerState?: string;
  AlarmSummary?: AlarmSummary;
  ManagementMode?: string;
}

export interface AlarmSummary {
  Critical?: number;
  Warning?: number;
  Info?: number;
}

// Alarm Types
export interface Alarm {
  Moid: string;
  Name: string;
  Severity: string;
  Description: string;
  AffectedMoId?: string;
  AffectedMoType?: string;
  Acknowledge?: string;
  CreationTime?: string;
}
