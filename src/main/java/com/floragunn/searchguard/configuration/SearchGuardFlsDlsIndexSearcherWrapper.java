/*
 * Copyright 2016-2017 by floragunn GmbH - All rights reserved
 *
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed here is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * This software is free of charge for non-commercial and academic use.
 * For commercial use in a production environment you have to obtain a license
 * from https://floragunn.com
 *
 */

package com.floragunn.searchguard.configuration;

import java.io.IOException;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.join.BitSetProducer;
import org.elasticsearch.cluster.service.ClusterService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.index.IndexService;
import org.elasticsearch.index.cache.bitset.BitsetFilterCache;
import org.elasticsearch.index.engine.EngineException;
import org.elasticsearch.index.mapper.MapperService;
import org.elasticsearch.index.shard.ShardId;
import org.elasticsearch.index.shard.ShardUtils;

import com.floragunn.searchguard.auditlog.AuditLog;
import com.floragunn.searchguard.compliance.ComplianceConfig;
import com.floragunn.searchguard.compliance.ComplianceIndexingOperationListener;
import com.floragunn.searchguard.support.ConfigConstants;
import com.floragunn.searchguard.support.HeaderHelper;
import com.floragunn.searchguard.support.SgUtils;
import com.google.common.collect.Sets;

public class SearchGuardFlsDlsIndexSearcherWrapper extends SearchGuardIndexSearcherWrapper {

    private static final Set<String> metaFields = Sets.union(Sets.newHashSet("_source", "_version"),
            Sets.newHashSet(MapperService.getAllMetaFields()));
    private final ClusterService clusterService;
    private final IndexService indexService;
    private final ComplianceConfig complianceConfig;
    private final AuditLog auditlog;

    public SearchGuardFlsDlsIndexSearcherWrapper(final IndexService indexService, final Settings settings,
            final AdminDNs adminDNs, final ClusterService clusterService, final AuditLog auditlog,
            final ComplianceIndexingOperationListener ciol, final ComplianceConfig complianceConfig) {
        super(indexService, settings, adminDNs);
        ciol.setIs(indexService);
        this.clusterService = clusterService;
        this.indexService = indexService;
        this.complianceConfig = complianceConfig;
        this.auditlog = auditlog;
    }

    @SuppressWarnings("unchecked")
    @Override
    protected DirectoryReader dlsFlsWrap(final DirectoryReader reader, boolean isAdmin) throws IOException {

        final ShardId shardId = ShardUtils.extractShardId(reader); 
        
        Set<String> flsFields = null;
        Set<String> maskedFields = null;
        BitSetProducer bsp = null;

        if(!isAdmin) {

            final Map<String, Set<String>> allowedFlsFields = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.SG_FLS_FIELDS_HEADER);
            final Map<String, Set<String>> queries = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.SG_DLS_QUERY_HEADER);
            final Map<String, Set<String>> maskedFieldsMap = (Map<String, Set<String>>) HeaderHelper.deserializeSafeFromHeader(threadContext,
                    ConfigConstants.SG_MASKED_FIELD_HEADER);

            final String flsEval = SgUtils.evalMap(allowedFlsFields, index.getName());
            final String dlsEval = SgUtils.evalMap(queries, index.getName());
            final String maskedEval = SgUtils.evalMap(maskedFieldsMap, index.getName());

            if (flsEval != null) {
                flsFields = new HashSet<>(metaFields);
                flsFields.addAll(allowedFlsFields.get(flsEval));
            }

            
            
            if (dlsEval != null) { 
                final Set<String> unparsedDlsQueries = queries.get(dlsEval);
                if(unparsedDlsQueries != null && !unparsedDlsQueries.isEmpty()) { 
                    final BitsetFilterCache bsfc = this.indexService.cache().bitsetFilterCache();
                    //disable reader optimizations
                    final Query dlsQuery = DlsQueryParser.parse(unparsedDlsQueries, this.indexService.newQueryShardContext(shardId.getId(), null, null, null)
                            , this.indexService.xContentRegistry());
                    bsp = dlsQuery==null?null:bsfc.getBitSetProducer(dlsQuery);
                }
            }
            
            if (maskedEval != null) {
                maskedFields = new HashSet<>();
                maskedFields.addAll(maskedFieldsMap.get(maskedEval));
            }
        }
        
        return new DlsFlsFilterLeafReader.DlsFlsDirectoryReader(reader, flsFields, bsp,
                indexService, threadContext, clusterService, complianceConfig, auditlog, maskedFields, shardId);
    }


    @Override
    protected IndexSearcher dlsFlsWrap(final IndexSearcher searcher, boolean isAdmin) throws EngineException {

        if(searcher.getIndexReader().getClass() != DlsFlsFilterLeafReader.DlsFlsDirectoryReader.class
                && searcher.getIndexReader().getClass() != EmptyFilterLeafReader.EmptyDirectoryReader.class) {
            throw new RuntimeException("Unexpected index reader class "+searcher.getIndexReader().getClass());
        }

        return searcher;
    }
}
