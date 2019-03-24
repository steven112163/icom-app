/*
 * Copyright 2019-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.icom.app;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.Ip4Address;
import org.onlab.packet.ARP;
import org.onlab.packet.MacAddress;

import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;

import org.onosproject.net.ConnectPoint;
import org.onosproject.net.Host;
import org.onosproject.net.HostId;
import org.onosproject.net.Path;
import org.onosproject.net.PortNumber;

import org.onosproject.net.host.HostService;

import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.onosproject.net.packet.InboundPacket;

import org.onosproject.net.topology.TopologyEvent;
import org.onosproject.net.topology.TopologyListener;
import org.onosproject.net.topology.TopologyService;

import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.flow.FlowRuleService;

import org.onosproject.net.flowobjective.DefaultForwardingObjective;
import org.onosproject.net.flowobjective.ForwardingObjective;
import org.onosproject.net.flowobjective.FlowObjectiveService;

import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Deactivate;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.Service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.Iterator;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true)
public class Communication {
	
	private static final int DEFAULT_TIMEOUT = 10;
	private static final int DEFAULT_PRIORITY = 49000;
	
	private final Logger log = LoggerFactory.getLogger(getClass());
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected TopologyService topologyService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected PacketService packetService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected HostService hostService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected FlowRuleService flowRuleService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected CoreService coreService;
	
	@Reference(cardinality = ReferenceCardinality.MANDATORY_UNARY)
	protected FlowObjectiveService flowObjectiveService;
	
	private CommunicationPacketProcessor processor = new CommunicationPacketProcessor();
	
	private ApplicationId appId;
	
	@Activate
	protected void activate() {
		appId = coreService.registerApplication("org.icom.app");
		packetService.addProcessor(processor, PacketProcessor.director(2));
		requestPackets();
		
		log.info("Started", appId.id());
	}
	
	@Deactivate
	protected void deactivate() {
		cancelPackets();
		flowRuleService.removeFlowRulesById(appId);
		packetService.removeProcessor(processor);
		processor = null;
		
		log.info("Stopped");
	}
	
	/**
	 * Request packet-in via packet service
	 */
	private void requestPackets() {
		TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
				.matchEthType(Ethernet.TYPE_ARP);
		packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
		
		selector = DefaultTrafficSelector.builder()
				.matchEthType(Ethernet.TYPE_IPV4)
				.matchIPProtocol(IPv4.PROTOCOL_ICMP);
		packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
	}
	
	/**
	 * Cancel request for packet-in via packet service
	 */
	private void cancelPackets() {
		TrafficSelector.Builder selector = DefaultTrafficSelector.builder()
				.matchEthType(Ethernet.TYPE_ARP);
		packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
		
		selector = DefaultTrafficSelector.builder()
				.matchEthType(Ethernet.TYPE_IPV4)
				.matchIPProtocol(IPv4.PROTOCOL_ICMP);
		packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
	}
	
	/**
	 * Packet processor responsible for forwarding communication packets
	 */
	private class CommunicationPacketProcessor implements PacketProcessor {
		/**
		 * Process packets
		 *
		 * @param context content of the incoming message
		 */
		@Override
		public void process(PacketContext context) {
			// Stop processing if the packet has been handled, since we
			// con't do any more to it.
			if (context.isHandled()) {
				return;
			}
			
			InboundPacket pkt = context.inPacket();
			Ethernet ethPkt = pkt.parsed();
			
			// Do not process null packet.
			if (ethPkt == null) {
				return;
			}
			
			// Make two processors to handle ARP packets and ICMP packets.
			if (ethPkt.getEtherType() == Ethernet.TYPE_ARP) {
				log.info("It's ARP packet!!!\n");
				processArpPacket(context, pkt, ethPkt);
			} else if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
				IPv4 ipv4Pkt = (IPv4) ethPkt.getPayload();
				if (ipv4Pkt.getProtocol() == IPv4.PROTOCOL_ICMP) {
					log.info("It's ICMP packet!!!\n");
					processIcmpPacket(context, pkt, ethPkt);
				}
			}
		}
		
		/**
		 * Forward ARP packets
		 *
		 * @param context content of the incoming message
		 * @param pkt the original packet
		 * @param packet the ethernet payload
		 */
		private void processArpPacket(PacketContext context, InboundPacket pkt, Ethernet ethPkt) {
			ARP arpPkt = (ARP) ethPkt.getPayload();
			
			if (arpPkt.getOpCode() == ARP.OP_REQUEST) {
				log.info("ARP request!!!\n");
				//hostService.requestMAC(Ip4Address(arpPkt.getTargetProtocolAddress()));
				Set<Host> hosts = hostService.getHostsByIp(Ip4Address.valueOf(arpPkt.getTargetProtocolAddress()));
				
				// ARP fails if there are two hosts with the same IP or no such host
				if (hosts.size() > 1 ) {
					log.warn("Two hosts with the same IP!!!\n");
					return;
				} else if (hosts.size() == 0) {
					log.warn("No such host!!!\n");
					return;
				}
				
				Iterator it = hosts.iterator();
				Host dst = (Host) it.next();
				log.info("Find the host!!!\n");
				
				findPathAndInstallRule(context, pkt, ethPkt, dst);
			} else if (arpPkt.getOpCode() == ARP.OP_REPLY) {
				log.info("ARP reply!!!\n");
				
				HostId dstId = HostId.hostId(MacAddress.valueOf(arpPkt.getTargetHardwareAddress()));
				Host dst = hostService.getHost(dstId);
				
				findPathAndInstallRule(context, pkt, ethPkt, dst);
			}
		}
		
		/**
		 * Forward ICMP packets
		 *
		 * @param context content of the incoming message
		 * @param pkt the original packet
		 * @param ethPkt the ethernet payload
		 */
		private void processIcmpPacket(PacketContext context, InboundPacket pkt, Ethernet ethPkt) {
			HostId dstId = HostId.hostId(ethPkt.getDestinationMAC());
			Host dst = hostService.getHost(dstId);
			
			findPathAndInstallRule(context, pkt, ethPkt, dst);
		}
	}
	
	/**
	 * Find the way to the destination and install rule on a switch
	 *
	 * @param context content of the incoming message
	 * @param pkt the original packet
	 * @param ethPkt the Ethernet payload
	 * @param dst destination host
	 */
	private void findPathAndInstallRule(PacketContext context, InboundPacket pkt, Ethernet ethPkt, Host dst) {
		// Is the packet on an edge switch that the destination is on? If so,
		// simply forward out to the destination and bail.            
		if (pkt.receivedFrom().deviceId().equals(dst.location().deviceId())) {
			if (!context.inPacket().receivedFrom().port().equals(dst.location().port())) {
				log.info("Packet is on edge switch!!!\n");
				installRule(context, dst.location().port());
			}
			return;
		}
		
		// The packet is not on edge switch, find a path to the destination.
		Set<Path> paths = topologyService.getPaths(topologyService.currentTopology(),
													   pkt.receivedFrom().deviceId(),
													   dst.location().deviceId());
		
		// If there are no paths, flood and bail.
		if (paths.isEmpty()) {
			log.warn("Packet floods!!!\n");
			flood(context);
			return;
		}
		
		// Otherwise, pick a path that does not lead back to where the packet
		// came from; if no such path, flood and bail.
		Path path = pickForwardPathIfPossible(paths, pkt.receivedFrom().port());
		if (path == null) {
			log.warn("Packet doesn't know where to go from here {} for {} -> {}\n",
			pkt.receivedFrom(), ethPkt.getSourceMAC(), ethPkt.getDestinationMAC());
			flood(context);
			return;
		}
		
		// Otherwise forward and be done with it.
		installRule(context, path.src().port());
	}
	
	/**
	 * flood the packet
	 *
	 * @param context content of the incoming message
	 */
	private void flood(PacketContext context) {
		if (topologyService.isBroadcastPoint(topologyService.currentTopology(),
											 context.inPacket().receivedFrom())) {
			packetOut(context, PortNumber.FLOOD);
		} else {
			context.block();
		}
	}
	
	/**
	 * Send the packet out from the port
	 *
	 * @param context content of the incoming message
	 * @param portNumber output port of the packet
	 */
	private void packetOut(PacketContext context, PortNumber portNumber) {
		context.treatmentBuilder().setOutput(portNumber);
		context.send();
	}
	
	/**
	 * Pick a path that does not lead back to where the packet
	 * came from
	 *
	 * @param paths all paths that can lead to the destination
	 * @param notToPort the port that the packet came from
	 */
	private Path pickForwardPathIfPossible(Set<Path> paths, PortNumber notToPort) {
		for (Path path : paths) {
			if (!path.src().port().equals(notToPort)) {
				return path;
			}
		}
		return null;
	}
	
	/**
	 * Install flow rules on a switch
	 *
	 * @param context content of the incoming message
	 * @param portNumber output port defined in the flow rule
	 */
	private void installRule(PacketContext context, PortNumber portNumber) {
		TrafficSelector.Builder selectorBuilder = DefaultTrafficSelector.builder();
		InboundPacket pkt = context.inPacket();
		Ethernet ethPkt = pkt.parsed();
		
		selectorBuilder.matchEthSrc(ethPkt.getSourceMAC())
				.matchEthDst(ethPkt.getDestinationMAC());
		
		TrafficTreatment treatment = DefaultTrafficTreatment.builder()
				.setOutput(portNumber)
				.build();
		
		ForwardingObjective forwardingObjective = DefaultForwardingObjective.builder()
				.withSelector(selectorBuilder.build())
				.withTreatment(treatment)
				.withPriority(DEFAULT_PRIORITY)
				.withFlag(ForwardingObjective.Flag.VERSATILE)
				.fromApp(appId)
				.makeTemporary(DEFAULT_TIMEOUT)
				.add();
		
		flowObjectiveService.forward(context.inPacket().receivedFrom().deviceId(), forwardingObjective);
		packetOut(context, portNumber);
	}
}
