--
-- PostgreSQL database dump
--

-- Dumped from database version 16.1
-- Dumped by pg_dump version 16.1

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: admin_event_entity; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.admin_event_entity (
    id character varying(36) NOT NULL,
    admin_event_time bigint,
    realm_id character varying(255),
    operation_type character varying(255),
    auth_realm_id character varying(255),
    auth_client_id character varying(255),
    auth_user_id character varying(255),
    ip_address character varying(255),
    resource_path character varying(2550),
    representation text,
    error character varying(255),
    resource_type character varying(64)
);


ALTER TABLE public.admin_event_entity OWNER TO admin;

--
-- Name: associated_policy; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.associated_policy (
    policy_id character varying(36) NOT NULL,
    associated_policy_id character varying(36) NOT NULL
);


ALTER TABLE public.associated_policy OWNER TO admin;

--
-- Name: authentication_execution; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.authentication_execution (
    id character varying(36) NOT NULL,
    alias character varying(255),
    authenticator character varying(36),
    realm_id character varying(36),
    flow_id character varying(36),
    requirement integer,
    priority integer,
    authenticator_flow boolean DEFAULT false NOT NULL,
    auth_flow_id character varying(36),
    auth_config character varying(36)
);


ALTER TABLE public.authentication_execution OWNER TO admin;

--
-- Name: authentication_flow; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.authentication_flow (
    id character varying(36) NOT NULL,
    alias character varying(255),
    description character varying(255),
    realm_id character varying(36),
    provider_id character varying(36) DEFAULT 'basic-flow'::character varying NOT NULL,
    top_level boolean DEFAULT false NOT NULL,
    built_in boolean DEFAULT false NOT NULL
);


ALTER TABLE public.authentication_flow OWNER TO admin;

--
-- Name: authenticator_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.authenticator_config (
    id character varying(36) NOT NULL,
    alias character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.authenticator_config OWNER TO admin;

--
-- Name: authenticator_config_entry; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.authenticator_config_entry (
    authenticator_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.authenticator_config_entry OWNER TO admin;

--
-- Name: broker_link; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.broker_link (
    identity_provider character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL,
    broker_user_id character varying(255),
    broker_username character varying(255),
    token text,
    user_id character varying(255) NOT NULL
);


ALTER TABLE public.broker_link OWNER TO admin;

--
-- Name: client; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client (
    id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    full_scope_allowed boolean DEFAULT false NOT NULL,
    client_id character varying(255),
    not_before integer,
    public_client boolean DEFAULT false NOT NULL,
    secret character varying(255),
    base_url character varying(255),
    bearer_only boolean DEFAULT false NOT NULL,
    management_url character varying(255),
    surrogate_auth_required boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    protocol character varying(255),
    node_rereg_timeout integer DEFAULT 0,
    frontchannel_logout boolean DEFAULT false NOT NULL,
    consent_required boolean DEFAULT false NOT NULL,
    name character varying(255),
    service_accounts_enabled boolean DEFAULT false NOT NULL,
    client_authenticator_type character varying(255),
    root_url character varying(255),
    description character varying(255),
    registration_token character varying(255),
    standard_flow_enabled boolean DEFAULT true NOT NULL,
    implicit_flow_enabled boolean DEFAULT false NOT NULL,
    direct_access_grants_enabled boolean DEFAULT false NOT NULL,
    always_display_in_console boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client OWNER TO admin;

--
-- Name: client_attributes; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_attributes (
    client_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.client_attributes OWNER TO admin;

--
-- Name: client_auth_flow_bindings; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_auth_flow_bindings (
    client_id character varying(36) NOT NULL,
    flow_id character varying(36),
    binding_name character varying(255) NOT NULL
);


ALTER TABLE public.client_auth_flow_bindings OWNER TO admin;

--
-- Name: client_initial_access; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_initial_access (
    id character varying(36) NOT NULL,
    realm_id character varying(36) NOT NULL,
    "timestamp" integer,
    expiration integer,
    count integer,
    remaining_count integer
);


ALTER TABLE public.client_initial_access OWNER TO admin;

--
-- Name: client_node_registrations; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_node_registrations (
    client_id character varying(36) NOT NULL,
    value integer,
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_node_registrations OWNER TO admin;

--
-- Name: client_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_scope (
    id character varying(36) NOT NULL,
    name character varying(255),
    realm_id character varying(36),
    description character varying(255),
    protocol character varying(255)
);


ALTER TABLE public.client_scope OWNER TO admin;

--
-- Name: client_scope_attributes; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_scope_attributes (
    scope_id character varying(36) NOT NULL,
    value character varying(2048),
    name character varying(255) NOT NULL
);


ALTER TABLE public.client_scope_attributes OWNER TO admin;

--
-- Name: client_scope_client; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_scope_client (
    client_id character varying(255) NOT NULL,
    scope_id character varying(255) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.client_scope_client OWNER TO admin;

--
-- Name: client_scope_role_mapping; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.client_scope_role_mapping (
    scope_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.client_scope_role_mapping OWNER TO admin;

--
-- Name: component; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.component (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_id character varying(36),
    provider_id character varying(36),
    provider_type character varying(255),
    realm_id character varying(36),
    sub_type character varying(255)
);


ALTER TABLE public.component OWNER TO admin;

--
-- Name: component_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.component_config (
    id character varying(36) NOT NULL,
    component_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.component_config OWNER TO admin;

--
-- Name: composite_role; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.composite_role (
    composite character varying(36) NOT NULL,
    child_role character varying(36) NOT NULL
);


ALTER TABLE public.composite_role OWNER TO admin;

--
-- Name: credential; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    user_id character varying(36),
    created_date bigint,
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer
);


ALTER TABLE public.credential OWNER TO admin;

--
-- Name: databasechangelog; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.databasechangelog (
    id character varying(255) NOT NULL,
    author character varying(255) NOT NULL,
    filename character varying(255) NOT NULL,
    dateexecuted timestamp without time zone NOT NULL,
    orderexecuted integer NOT NULL,
    exectype character varying(10) NOT NULL,
    md5sum character varying(35),
    description character varying(255),
    comments character varying(255),
    tag character varying(255),
    liquibase character varying(20),
    contexts character varying(255),
    labels character varying(255),
    deployment_id character varying(10)
);


ALTER TABLE public.databasechangelog OWNER TO admin;

--
-- Name: databasechangeloglock; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.databasechangeloglock (
    id integer NOT NULL,
    locked boolean NOT NULL,
    lockgranted timestamp without time zone,
    lockedby character varying(255)
);


ALTER TABLE public.databasechangeloglock OWNER TO admin;

--
-- Name: default_client_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.default_client_scope (
    realm_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL,
    default_scope boolean DEFAULT false NOT NULL
);


ALTER TABLE public.default_client_scope OWNER TO admin;

--
-- Name: event_entity; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.event_entity (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    details_json character varying(2550),
    error character varying(255),
    ip_address character varying(255),
    realm_id character varying(255),
    session_id character varying(255),
    event_time bigint,
    type character varying(255),
    user_id character varying(255),
    details_json_long_value text
);


ALTER TABLE public.event_entity OWNER TO admin;

--
-- Name: fed_user_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_attribute (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    value character varying(2024),
    long_value_hash bytea,
    long_value_hash_lower_case bytea,
    long_value text
);


ALTER TABLE public.fed_user_attribute OWNER TO admin;

--
-- Name: fed_user_consent; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.fed_user_consent OWNER TO admin;

--
-- Name: fed_user_consent_cl_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_consent_cl_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.fed_user_consent_cl_scope OWNER TO admin;

--
-- Name: fed_user_credential; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_credential (
    id character varying(36) NOT NULL,
    salt bytea,
    type character varying(255),
    created_date bigint,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36),
    user_label character varying(255),
    secret_data text,
    credential_data text,
    priority integer
);


ALTER TABLE public.fed_user_credential OWNER TO admin;

--
-- Name: fed_user_group_membership; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_group_membership OWNER TO admin;

--
-- Name: fed_user_required_action; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_required_action (
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_required_action OWNER TO admin;

--
-- Name: fed_user_role_mapping; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.fed_user_role_mapping (
    role_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    storage_provider_id character varying(36)
);


ALTER TABLE public.fed_user_role_mapping OWNER TO admin;

--
-- Name: federated_identity; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.federated_identity (
    identity_provider character varying(255) NOT NULL,
    realm_id character varying(36),
    federated_user_id character varying(255),
    federated_username character varying(255),
    token text,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_identity OWNER TO admin;

--
-- Name: federated_user; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.federated_user (
    id character varying(255) NOT NULL,
    storage_provider_id character varying(255),
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.federated_user OWNER TO admin;

--
-- Name: group_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.group_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_attribute OWNER TO admin;

--
-- Name: group_role_mapping; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.group_role_mapping (
    role_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.group_role_mapping OWNER TO admin;

--
-- Name: identity_provider; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.identity_provider (
    internal_id character varying(36) NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    provider_alias character varying(255),
    provider_id character varying(255),
    store_token boolean DEFAULT false NOT NULL,
    authenticate_by_default boolean DEFAULT false NOT NULL,
    realm_id character varying(36),
    add_token_role boolean DEFAULT true NOT NULL,
    trust_email boolean DEFAULT false NOT NULL,
    first_broker_login_flow_id character varying(36),
    post_broker_login_flow_id character varying(36),
    provider_display_name character varying(255),
    link_only boolean DEFAULT false NOT NULL,
    organization_id character varying(255),
    hide_on_login boolean DEFAULT false
);


ALTER TABLE public.identity_provider OWNER TO admin;

--
-- Name: identity_provider_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.identity_provider_config (
    identity_provider_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.identity_provider_config OWNER TO admin;

--
-- Name: identity_provider_mapper; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.identity_provider_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    idp_alias character varying(255) NOT NULL,
    idp_mapper_name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.identity_provider_mapper OWNER TO admin;

--
-- Name: idp_mapper_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.idp_mapper_config (
    idp_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.idp_mapper_config OWNER TO admin;

--
-- Name: keycloak_group; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.keycloak_group (
    id character varying(36) NOT NULL,
    name character varying(255),
    parent_group character varying(36) NOT NULL,
    realm_id character varying(36),
    type integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.keycloak_group OWNER TO admin;

--
-- Name: keycloak_role; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.keycloak_role (
    id character varying(36) NOT NULL,
    client_realm_constraint character varying(255),
    client_role boolean DEFAULT false NOT NULL,
    description character varying(255),
    name character varying(255),
    realm_id character varying(255),
    client character varying(36),
    realm character varying(36)
);


ALTER TABLE public.keycloak_role OWNER TO admin;

--
-- Name: migration_model; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.migration_model (
    id character varying(36) NOT NULL,
    version character varying(36),
    update_time bigint DEFAULT 0 NOT NULL
);


ALTER TABLE public.migration_model OWNER TO admin;

--
-- Name: offline_client_session; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.offline_client_session (
    user_session_id character varying(36) NOT NULL,
    client_id character varying(255) NOT NULL,
    offline_flag character varying(4) NOT NULL,
    "timestamp" integer,
    data text,
    client_storage_provider character varying(36) DEFAULT 'local'::character varying NOT NULL,
    external_client_id character varying(255) DEFAULT 'local'::character varying NOT NULL,
    version integer DEFAULT 0
);


ALTER TABLE public.offline_client_session OWNER TO admin;

--
-- Name: offline_user_session; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.offline_user_session (
    user_session_id character varying(36) NOT NULL,
    user_id character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    created_on integer NOT NULL,
    offline_flag character varying(4) NOT NULL,
    data text,
    last_session_refresh integer DEFAULT 0 NOT NULL,
    broker_session_id character varying(1024),
    version integer DEFAULT 0
);


ALTER TABLE public.offline_user_session OWNER TO admin;

--
-- Name: org; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.org (
    id character varying(255) NOT NULL,
    enabled boolean NOT NULL,
    realm_id character varying(255) NOT NULL,
    group_id character varying(255) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(4000),
    alias character varying(255) NOT NULL,
    redirect_url character varying(2048)
);


ALTER TABLE public.org OWNER TO admin;

--
-- Name: org_domain; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.org_domain (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    verified boolean NOT NULL,
    org_id character varying(255) NOT NULL
);


ALTER TABLE public.org_domain OWNER TO admin;

--
-- Name: policy_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.policy_config (
    policy_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value text
);


ALTER TABLE public.policy_config OWNER TO admin;

--
-- Name: protocol_mapper; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.protocol_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    protocol character varying(255) NOT NULL,
    protocol_mapper_name character varying(255) NOT NULL,
    client_id character varying(36),
    client_scope_id character varying(36)
);


ALTER TABLE public.protocol_mapper OWNER TO admin;

--
-- Name: protocol_mapper_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.protocol_mapper_config (
    protocol_mapper_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.protocol_mapper_config OWNER TO admin;

--
-- Name: realm; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm (
    id character varying(36) NOT NULL,
    access_code_lifespan integer,
    user_action_lifespan integer,
    access_token_lifespan integer,
    account_theme character varying(255),
    admin_theme character varying(255),
    email_theme character varying(255),
    enabled boolean DEFAULT false NOT NULL,
    events_enabled boolean DEFAULT false NOT NULL,
    events_expiration bigint,
    login_theme character varying(255),
    name character varying(255),
    not_before integer,
    password_policy character varying(2550),
    registration_allowed boolean DEFAULT false NOT NULL,
    remember_me boolean DEFAULT false NOT NULL,
    reset_password_allowed boolean DEFAULT false NOT NULL,
    social boolean DEFAULT false NOT NULL,
    ssl_required character varying(255),
    sso_idle_timeout integer,
    sso_max_lifespan integer,
    update_profile_on_soc_login boolean DEFAULT false NOT NULL,
    verify_email boolean DEFAULT false NOT NULL,
    master_admin_client character varying(36),
    login_lifespan integer,
    internationalization_enabled boolean DEFAULT false NOT NULL,
    default_locale character varying(255),
    reg_email_as_username boolean DEFAULT false NOT NULL,
    admin_events_enabled boolean DEFAULT false NOT NULL,
    admin_events_details_enabled boolean DEFAULT false NOT NULL,
    edit_username_allowed boolean DEFAULT false NOT NULL,
    otp_policy_counter integer DEFAULT 0,
    otp_policy_window integer DEFAULT 1,
    otp_policy_period integer DEFAULT 30,
    otp_policy_digits integer DEFAULT 6,
    otp_policy_alg character varying(36) DEFAULT 'HmacSHA1'::character varying,
    otp_policy_type character varying(36) DEFAULT 'totp'::character varying,
    browser_flow character varying(36),
    registration_flow character varying(36),
    direct_grant_flow character varying(36),
    reset_credentials_flow character varying(36),
    client_auth_flow character varying(36),
    offline_session_idle_timeout integer DEFAULT 0,
    revoke_refresh_token boolean DEFAULT false NOT NULL,
    access_token_life_implicit integer DEFAULT 0,
    login_with_email_allowed boolean DEFAULT true NOT NULL,
    duplicate_emails_allowed boolean DEFAULT false NOT NULL,
    docker_auth_flow character varying(36),
    refresh_token_max_reuse integer DEFAULT 0,
    allow_user_managed_access boolean DEFAULT false NOT NULL,
    sso_max_lifespan_remember_me integer DEFAULT 0 NOT NULL,
    sso_idle_timeout_remember_me integer DEFAULT 0 NOT NULL,
    default_role character varying(255)
);


ALTER TABLE public.realm OWNER TO admin;

--
-- Name: realm_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_attribute (
    name character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL,
    value text
);


ALTER TABLE public.realm_attribute OWNER TO admin;

--
-- Name: realm_default_groups; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_default_groups (
    realm_id character varying(36) NOT NULL,
    group_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_default_groups OWNER TO admin;

--
-- Name: realm_enabled_event_types; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_enabled_event_types (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_enabled_event_types OWNER TO admin;

--
-- Name: realm_events_listeners; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_events_listeners (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_events_listeners OWNER TO admin;

--
-- Name: realm_localizations; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_localizations (
    realm_id character varying(255) NOT NULL,
    locale character varying(255) NOT NULL,
    texts text NOT NULL
);


ALTER TABLE public.realm_localizations OWNER TO admin;

--
-- Name: realm_required_credential; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_required_credential (
    type character varying(255) NOT NULL,
    form_label character varying(255),
    input boolean DEFAULT false NOT NULL,
    secret boolean DEFAULT false NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.realm_required_credential OWNER TO admin;

--
-- Name: realm_smtp_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_smtp_config (
    realm_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.realm_smtp_config OWNER TO admin;

--
-- Name: realm_supported_locales; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.realm_supported_locales (
    realm_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.realm_supported_locales OWNER TO admin;

--
-- Name: redirect_uris; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.redirect_uris (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.redirect_uris OWNER TO admin;

--
-- Name: required_action_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.required_action_config (
    required_action_id character varying(36) NOT NULL,
    value text,
    name character varying(255) NOT NULL
);


ALTER TABLE public.required_action_config OWNER TO admin;

--
-- Name: required_action_provider; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.required_action_provider (
    id character varying(36) NOT NULL,
    alias character varying(255),
    name character varying(255),
    realm_id character varying(36),
    enabled boolean DEFAULT false NOT NULL,
    default_action boolean DEFAULT false NOT NULL,
    provider_id character varying(255),
    priority integer
);


ALTER TABLE public.required_action_provider OWNER TO admin;

--
-- Name: resource_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_attribute (
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255),
    resource_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_attribute OWNER TO admin;

--
-- Name: resource_policy; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_policy (
    resource_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_policy OWNER TO admin;

--
-- Name: resource_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_scope (
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.resource_scope OWNER TO admin;

--
-- Name: resource_server; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_server (
    id character varying(36) NOT NULL,
    allow_rs_remote_mgmt boolean DEFAULT false NOT NULL,
    policy_enforce_mode smallint NOT NULL,
    decision_strategy smallint DEFAULT 1 NOT NULL
);


ALTER TABLE public.resource_server OWNER TO admin;

--
-- Name: resource_server_perm_ticket; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_server_perm_ticket (
    id character varying(36) NOT NULL,
    owner character varying(255) NOT NULL,
    requester character varying(255) NOT NULL,
    created_timestamp bigint NOT NULL,
    granted_timestamp bigint,
    resource_id character varying(36) NOT NULL,
    scope_id character varying(36),
    resource_server_id character varying(36) NOT NULL,
    policy_id character varying(36)
);


ALTER TABLE public.resource_server_perm_ticket OWNER TO admin;

--
-- Name: resource_server_policy; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_server_policy (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    description character varying(255),
    type character varying(255) NOT NULL,
    decision_strategy smallint,
    logic smallint,
    resource_server_id character varying(36) NOT NULL,
    owner character varying(255)
);


ALTER TABLE public.resource_server_policy OWNER TO admin;

--
-- Name: resource_server_resource; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_server_resource (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    type character varying(255),
    icon_uri character varying(255),
    owner character varying(255) NOT NULL,
    resource_server_id character varying(36) NOT NULL,
    owner_managed_access boolean DEFAULT false NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_resource OWNER TO admin;

--
-- Name: resource_server_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_server_scope (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    icon_uri character varying(255),
    resource_server_id character varying(36) NOT NULL,
    display_name character varying(255)
);


ALTER TABLE public.resource_server_scope OWNER TO admin;

--
-- Name: resource_uris; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.resource_uris (
    resource_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.resource_uris OWNER TO admin;

--
-- Name: revoked_token; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.revoked_token (
    id character varying(255) NOT NULL,
    expire bigint NOT NULL
);


ALTER TABLE public.revoked_token OWNER TO admin;

--
-- Name: role_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.role_attribute (
    id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    value character varying(255)
);


ALTER TABLE public.role_attribute OWNER TO admin;

--
-- Name: scope_mapping; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.scope_mapping (
    client_id character varying(36) NOT NULL,
    role_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_mapping OWNER TO admin;

--
-- Name: scope_policy; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.scope_policy (
    scope_id character varying(36) NOT NULL,
    policy_id character varying(36) NOT NULL
);


ALTER TABLE public.scope_policy OWNER TO admin;

--
-- Name: user_attribute; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_attribute (
    name character varying(255) NOT NULL,
    value character varying(255),
    user_id character varying(36) NOT NULL,
    id character varying(36) DEFAULT 'sybase-needs-something-here'::character varying NOT NULL,
    long_value_hash bytea,
    long_value_hash_lower_case bytea,
    long_value text
);


ALTER TABLE public.user_attribute OWNER TO admin;

--
-- Name: user_consent; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_consent (
    id character varying(36) NOT NULL,
    client_id character varying(255),
    user_id character varying(36) NOT NULL,
    created_date bigint,
    last_updated_date bigint,
    client_storage_provider character varying(36),
    external_client_id character varying(255)
);


ALTER TABLE public.user_consent OWNER TO admin;

--
-- Name: user_consent_client_scope; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_consent_client_scope (
    user_consent_id character varying(36) NOT NULL,
    scope_id character varying(36) NOT NULL
);


ALTER TABLE public.user_consent_client_scope OWNER TO admin;

--
-- Name: user_entity; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_entity (
    id character varying(36) NOT NULL,
    email character varying(255),
    email_constraint character varying(255),
    email_verified boolean DEFAULT false NOT NULL,
    enabled boolean DEFAULT false NOT NULL,
    federation_link character varying(255),
    first_name character varying(255),
    last_name character varying(255),
    realm_id character varying(255),
    username character varying(255),
    created_timestamp bigint,
    service_account_client_link character varying(255),
    not_before integer DEFAULT 0 NOT NULL
);


ALTER TABLE public.user_entity OWNER TO admin;

--
-- Name: user_federation_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_federation_config (
    user_federation_provider_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_config OWNER TO admin;

--
-- Name: user_federation_mapper; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_federation_mapper (
    id character varying(36) NOT NULL,
    name character varying(255) NOT NULL,
    federation_provider_id character varying(36) NOT NULL,
    federation_mapper_type character varying(255) NOT NULL,
    realm_id character varying(36) NOT NULL
);


ALTER TABLE public.user_federation_mapper OWNER TO admin;

--
-- Name: user_federation_mapper_config; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_federation_mapper_config (
    user_federation_mapper_id character varying(36) NOT NULL,
    value character varying(255),
    name character varying(255) NOT NULL
);


ALTER TABLE public.user_federation_mapper_config OWNER TO admin;

--
-- Name: user_federation_provider; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_federation_provider (
    id character varying(36) NOT NULL,
    changed_sync_period integer,
    display_name character varying(255),
    full_sync_period integer,
    last_sync integer,
    priority integer,
    provider_name character varying(255),
    realm_id character varying(36)
);


ALTER TABLE public.user_federation_provider OWNER TO admin;

--
-- Name: user_group_membership; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_group_membership (
    group_id character varying(36) NOT NULL,
    user_id character varying(36) NOT NULL,
    membership_type character varying(255) NOT NULL
);


ALTER TABLE public.user_group_membership OWNER TO admin;

--
-- Name: user_required_action; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_required_action (
    user_id character varying(36) NOT NULL,
    required_action character varying(255) DEFAULT ' '::character varying NOT NULL
);


ALTER TABLE public.user_required_action OWNER TO admin;

--
-- Name: user_role_mapping; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.user_role_mapping (
    role_id character varying(255) NOT NULL,
    user_id character varying(36) NOT NULL
);


ALTER TABLE public.user_role_mapping OWNER TO admin;

--
-- Name: username_login_failure; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.username_login_failure (
    realm_id character varying(36) NOT NULL,
    username character varying(255) NOT NULL,
    failed_login_not_before integer,
    last_failure bigint,
    last_ip_failure character varying(255),
    num_failures integer
);


ALTER TABLE public.username_login_failure OWNER TO admin;

--
-- Name: web_origins; Type: TABLE; Schema: public; Owner: admin
--

CREATE TABLE public.web_origins (
    client_id character varying(36) NOT NULL,
    value character varying(255) NOT NULL
);


ALTER TABLE public.web_origins OWNER TO admin;

--
-- Data for Name: admin_event_entity; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.admin_event_entity (id, admin_event_time, realm_id, operation_type, auth_realm_id, auth_client_id, auth_user_id, ip_address, resource_path, representation, error, resource_type) FROM stdin;
\.


--
-- Data for Name: associated_policy; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.associated_policy (policy_id, associated_policy_id) FROM stdin;
\.


--
-- Data for Name: authentication_execution; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.authentication_execution (id, alias, authenticator, realm_id, flow_id, requirement, priority, authenticator_flow, auth_flow_id, auth_config) FROM stdin;
987def3a-e234-4084-a6d6-8d54c2c1aad8	\N	auth-cookie	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	78446504-0b4c-4af0-ad14-873219332369	2	10	f	\N	\N
15e9d48e-8693-409a-ba5c-73e686ffb238	\N	auth-spnego	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	78446504-0b4c-4af0-ad14-873219332369	3	20	f	\N	\N
5ddda2d4-fc8e-4652-8b68-5f1d4fe9eaab	\N	identity-provider-redirector	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	78446504-0b4c-4af0-ad14-873219332369	2	25	f	\N	\N
e574d9bd-48bc-4c16-8e6d-1d05940b5fd4	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	78446504-0b4c-4af0-ad14-873219332369	2	30	t	6a0c9aae-e4fb-4ecf-a50b-fc02b8749fc5	\N
d51e0eec-1a9f-4ed7-9c58-13499a7a1741	\N	auth-username-password-form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6a0c9aae-e4fb-4ecf-a50b-fc02b8749fc5	0	10	f	\N	\N
4c6402ef-4d99-41fe-98ef-e4ed2de114c1	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6a0c9aae-e4fb-4ecf-a50b-fc02b8749fc5	1	20	t	bd34f85f-b155-4939-b810-b54e6e23ff6c	\N
a8f3473b-6575-4866-b1e2-f97813f95040	\N	conditional-user-configured	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	bd34f85f-b155-4939-b810-b54e6e23ff6c	0	10	f	\N	\N
c298c9b6-3da7-4ad4-88da-35cb303e923f	\N	auth-otp-form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	bd34f85f-b155-4939-b810-b54e6e23ff6c	0	20	f	\N	\N
15eb77b4-6fd8-4b6f-8e42-b906e957266a	\N	direct-grant-validate-username	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e0d57b8a-61c5-4c6d-82fc-1d1c3b1a3cf6	0	10	f	\N	\N
217b4bd2-de04-4781-983b-c493dfa10de5	\N	direct-grant-validate-password	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e0d57b8a-61c5-4c6d-82fc-1d1c3b1a3cf6	0	20	f	\N	\N
6fe2e9b4-78f9-4f12-ac2f-b1a3d247305a	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e0d57b8a-61c5-4c6d-82fc-1d1c3b1a3cf6	1	30	t	10ba598f-97f5-4cc3-9283-ac80a4a0409f	\N
2d4c8208-aae7-4ffd-9909-7756eacf2f03	\N	conditional-user-configured	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	10ba598f-97f5-4cc3-9283-ac80a4a0409f	0	10	f	\N	\N
96cbed16-3726-44e7-bef6-7c4dc8c3733b	\N	direct-grant-validate-otp	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	10ba598f-97f5-4cc3-9283-ac80a4a0409f	0	20	f	\N	\N
4ef51bde-1265-4c9e-8adf-492c40f82f50	\N	registration-page-form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c999d09a-a3df-4fc0-9363-f53186cbf71a	0	10	t	40416775-8135-47fb-9c8e-f5dddea32564	\N
5e1ac996-2b71-4dcc-ab68-068623d8a68d	\N	registration-user-creation	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	40416775-8135-47fb-9c8e-f5dddea32564	0	20	f	\N	\N
2c848f6d-46fc-4091-a707-3a68406d7d72	\N	registration-password-action	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	40416775-8135-47fb-9c8e-f5dddea32564	0	50	f	\N	\N
0165a4f8-5405-42fc-be61-65bea5bef880	\N	registration-recaptcha-action	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	40416775-8135-47fb-9c8e-f5dddea32564	3	60	f	\N	\N
33cfd96a-9d97-4f23-ba0a-97d53ab67acd	\N	registration-terms-and-conditions	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	40416775-8135-47fb-9c8e-f5dddea32564	3	70	f	\N	\N
24692917-0929-46a3-a494-4257c6505c80	\N	reset-credentials-choose-user	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	2557231a-a634-4c1d-a7f1-1992cfa00924	0	10	f	\N	\N
09935071-7f9c-4057-a10c-0242f62aeaaa	\N	reset-credential-email	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	2557231a-a634-4c1d-a7f1-1992cfa00924	0	20	f	\N	\N
b3fd8210-3440-47ce-be1b-4b472dcde63a	\N	reset-password	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	2557231a-a634-4c1d-a7f1-1992cfa00924	0	30	f	\N	\N
cdc7960d-1a42-4daa-9c53-6b536bc73763	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	2557231a-a634-4c1d-a7f1-1992cfa00924	1	40	t	f0bd1252-4fed-403d-9b57-cc6f5f6b2919	\N
69fb1e23-779b-4a56-9c19-20e28afaefca	\N	conditional-user-configured	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f0bd1252-4fed-403d-9b57-cc6f5f6b2919	0	10	f	\N	\N
f40b3982-325d-4017-9913-93ea441c68fc	\N	reset-otp	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f0bd1252-4fed-403d-9b57-cc6f5f6b2919	0	20	f	\N	\N
6dc69eaf-3ff3-4b8e-805a-9c9cce891e13	\N	client-secret	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	d4128574-8dfe-42ed-b9d9-d032451a6828	2	10	f	\N	\N
987928c6-8a26-4595-b294-30101951060a	\N	client-jwt	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	d4128574-8dfe-42ed-b9d9-d032451a6828	2	20	f	\N	\N
757f868c-c880-4bcf-81bb-bf7a6019e8b9	\N	client-secret-jwt	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	d4128574-8dfe-42ed-b9d9-d032451a6828	2	30	f	\N	\N
76fff2c8-2f08-4d05-8bda-5b364837b804	\N	client-x509	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	d4128574-8dfe-42ed-b9d9-d032451a6828	2	40	f	\N	\N
909c5c8a-e204-4fbc-9f38-5c2a7e0b537b	\N	idp-review-profile	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c13a3512-6b0e-4198-8f81-6dacf5d80d57	0	10	f	\N	8a2f1bb9-2f49-4651-b9d4-5e0856344577
adfe68bd-9f5a-4ff4-be5e-ae00f3052476	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c13a3512-6b0e-4198-8f81-6dacf5d80d57	0	20	t	8be42ca2-de81-4aca-b724-cf94f23121e0	\N
cd3fa915-0566-48cf-b94b-ee1dabb1503f	\N	idp-create-user-if-unique	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	8be42ca2-de81-4aca-b724-cf94f23121e0	2	10	f	\N	f6608271-7113-4483-9a37-ba9fd9cb86f8
071cac10-242a-4f37-bdeb-b8b1d55293c3	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	8be42ca2-de81-4aca-b724-cf94f23121e0	2	20	t	52dba704-3f7c-41bf-8a66-542dccdfd5fb	\N
562485e3-5065-4a21-8b3f-73cf9c151719	\N	idp-confirm-link	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	52dba704-3f7c-41bf-8a66-542dccdfd5fb	0	10	f	\N	\N
2c8d5557-88b0-4afb-bb9f-1ca76662540d	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	52dba704-3f7c-41bf-8a66-542dccdfd5fb	0	20	t	847ce45c-1160-4f98-9318-0fd4726b0d61	\N
e6b00b1b-675e-492f-9d0c-9ccbba8f2f13	\N	idp-email-verification	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	847ce45c-1160-4f98-9318-0fd4726b0d61	2	10	f	\N	\N
d5d2a32f-f248-41e4-9587-e46f540fa304	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	847ce45c-1160-4f98-9318-0fd4726b0d61	2	20	t	c40fff6a-c627-4e2a-9aba-b9d77a49cd16	\N
f18a895a-5802-4221-b7f3-084fa3393738	\N	idp-username-password-form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c40fff6a-c627-4e2a-9aba-b9d77a49cd16	0	10	f	\N	\N
c990f2f0-94b7-4256-9c29-b02552666efa	\N	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c40fff6a-c627-4e2a-9aba-b9d77a49cd16	1	20	t	24149f98-8b6a-4949-a8da-7457a0b142e9	\N
0aef606b-e422-47e2-9c80-8c37fbdaf19c	\N	conditional-user-configured	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	24149f98-8b6a-4949-a8da-7457a0b142e9	0	10	f	\N	\N
4ff3d5f4-2597-4a05-a870-e165aeb1b0f0	\N	auth-otp-form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	24149f98-8b6a-4949-a8da-7457a0b142e9	0	20	f	\N	\N
862fec6d-1981-4e72-a399-78b48730bcae	\N	http-basic-authenticator	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	1612f2e8-3660-4f4b-bcf4-1d7b50b125be	0	10	f	\N	\N
ad6f41b1-0993-4ea4-852e-60077b8d913e	\N	docker-http-basic-authenticator	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	028aa2e6-43d2-4060-829c-72c105543119	0	10	f	\N	\N
d1840f4e-3a64-4300-aabb-109e3ec454a8	\N	auth-cookie	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	3ac63505-a8ac-4176-815a-fa38d513c145	2	10	f	\N	\N
3f0adbf7-8e7f-4a8f-af86-4730c39d0fa4	\N	auth-spnego	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	3ac63505-a8ac-4176-815a-fa38d513c145	3	20	f	\N	\N
36d6d847-9c4a-4508-8cb7-d1aa0d085c37	\N	identity-provider-redirector	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	3ac63505-a8ac-4176-815a-fa38d513c145	2	25	f	\N	\N
d2f1d28d-ea28-4587-a1bc-cbd6644ee41d	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	3ac63505-a8ac-4176-815a-fa38d513c145	2	30	t	1a94692c-8ceb-49b6-b83d-e7a7d3da2846	\N
7506c20a-dfed-4a9b-8032-6580aea53509	\N	auth-username-password-form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	1a94692c-8ceb-49b6-b83d-e7a7d3da2846	0	10	f	\N	\N
e4864299-f563-4595-92e3-02651b374153	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	1a94692c-8ceb-49b6-b83d-e7a7d3da2846	1	20	t	4e5e913f-a5ff-4732-abe6-82c049177507	\N
a71f5f43-b8c3-4f89-bf70-94cefc00d0cd	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	4e5e913f-a5ff-4732-abe6-82c049177507	0	10	f	\N	\N
d4f5d568-3169-4963-bbb1-b594bb501178	\N	auth-otp-form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	4e5e913f-a5ff-4732-abe6-82c049177507	0	20	f	\N	\N
c248c6b9-abd0-4a41-a57f-083bf23c11c2	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	3ac63505-a8ac-4176-815a-fa38d513c145	2	26	t	c9c7dc62-565e-42d6-b76b-aa29d5efa43e	\N
1c9bb685-2108-4481-99fa-f0a483325456	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	c9c7dc62-565e-42d6-b76b-aa29d5efa43e	1	10	t	33d7a1d3-48de-49a9-a040-d77f751a0523	\N
3bc62b33-02d4-4c86-bf15-6c988a6592d7	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	33d7a1d3-48de-49a9-a040-d77f751a0523	0	10	f	\N	\N
28e4decf-8ae9-4cd7-93b1-f4fffeb905de	\N	organization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	33d7a1d3-48de-49a9-a040-d77f751a0523	2	20	f	\N	\N
42e21748-fddb-4e6d-9842-73359432ea21	\N	direct-grant-validate-username	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	adabb682-8fe5-4142-a1ce-59c7e8219470	0	10	f	\N	\N
14593d83-0e51-4ae6-8843-69e2b26020e1	\N	direct-grant-validate-password	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	adabb682-8fe5-4142-a1ce-59c7e8219470	0	20	f	\N	\N
a7f4d8cb-d447-4504-a231-0de7b58cf70f	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	adabb682-8fe5-4142-a1ce-59c7e8219470	1	30	t	74b03ad4-8bc9-49c5-be44-fb37762ea98d	\N
15103c0d-8f75-48ca-9ea8-01c8e78f60a6	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	74b03ad4-8bc9-49c5-be44-fb37762ea98d	0	10	f	\N	\N
fa7c130a-70de-431f-bd80-37e3d04b33d2	\N	direct-grant-validate-otp	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	74b03ad4-8bc9-49c5-be44-fb37762ea98d	0	20	f	\N	\N
09aa7d76-2217-4acd-b0c2-5d35d01fc9da	\N	registration-page-form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	2bda16cd-a2ee-4899-9281-01120e271f39	0	10	t	e2ee3021-280a-4456-8491-636c795b619f	\N
9ab38770-534e-4afe-a751-e1e326e82ba5	\N	registration-user-creation	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e2ee3021-280a-4456-8491-636c795b619f	0	20	f	\N	\N
e213cfe1-f490-492f-9953-d51a7115fb4d	\N	registration-password-action	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e2ee3021-280a-4456-8491-636c795b619f	0	50	f	\N	\N
f1e5d943-c931-41cd-9a37-9c4c041599f1	\N	registration-recaptcha-action	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e2ee3021-280a-4456-8491-636c795b619f	3	60	f	\N	\N
a881a270-6461-471b-abc4-7dac1c887a46	\N	registration-terms-and-conditions	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e2ee3021-280a-4456-8491-636c795b619f	3	70	f	\N	\N
51452324-44cc-4034-a076-1e622716b795	\N	reset-credentials-choose-user	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	042e46e8-c183-4d61-8b08-ba48ceb00fd1	0	10	f	\N	\N
b2c4421c-3df4-45a3-92ef-e9b0f1c98a5f	\N	reset-credential-email	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	042e46e8-c183-4d61-8b08-ba48ceb00fd1	0	20	f	\N	\N
5f8b2a2d-87ce-4f4f-9885-3653ae4f1bfd	\N	reset-password	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	042e46e8-c183-4d61-8b08-ba48ceb00fd1	0	30	f	\N	\N
ca3f7674-61fa-4f65-8fdd-cfc0566b0f91	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	042e46e8-c183-4d61-8b08-ba48ceb00fd1	1	40	t	88959bdc-83f8-4464-a7ab-aafcb248b9cc	\N
61399d11-5461-48d3-9efd-54f774e3f61d	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	88959bdc-83f8-4464-a7ab-aafcb248b9cc	0	10	f	\N	\N
32e82e9a-f6aa-4f08-92b2-0d6841156cb6	\N	reset-otp	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	88959bdc-83f8-4464-a7ab-aafcb248b9cc	0	20	f	\N	\N
b889e679-64fe-4455-b86c-ff015eb5f38a	\N	client-secret	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	65c30146-5469-4da5-a010-dfad5eee7fdd	2	10	f	\N	\N
c8af3a71-8093-45ca-8e98-f51502c2a054	\N	client-jwt	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	65c30146-5469-4da5-a010-dfad5eee7fdd	2	20	f	\N	\N
534d557c-9471-4e0a-9d3c-d975e1534e22	\N	client-secret-jwt	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	65c30146-5469-4da5-a010-dfad5eee7fdd	2	30	f	\N	\N
ba56e397-bef3-41b9-a08f-9cc569fb1309	\N	client-x509	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	65c30146-5469-4da5-a010-dfad5eee7fdd	2	40	f	\N	\N
57de7260-fb05-4fe0-bf0b-3a95fd874e3e	\N	idp-review-profile	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e840cd3c-8a7c-408b-a232-efd488fbe293	0	10	f	\N	ec7cb439-8b32-44c7-a450-70c400f165ba
a79ffa21-2de3-48c1-8fd8-efb5b787edcc	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e840cd3c-8a7c-408b-a232-efd488fbe293	0	20	t	8ede821f-1184-4f20-ab6b-2bd013740234	\N
34e8ed85-1254-4467-a2e1-d9b09b5b0164	\N	idp-create-user-if-unique	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	8ede821f-1184-4f20-ab6b-2bd013740234	2	10	f	\N	2f9d6abc-6145-435a-8aee-0dbdb041358e
fe75373b-77c7-4626-a009-425e3b16d2c2	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	8ede821f-1184-4f20-ab6b-2bd013740234	2	20	t	a35e3e7d-3739-4ef7-8f0f-82d42fb5f2b0	\N
e9f47b30-119b-493c-8575-a65e16d7e5db	\N	idp-confirm-link	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	a35e3e7d-3739-4ef7-8f0f-82d42fb5f2b0	0	10	f	\N	\N
516f494b-ca27-4595-a4f6-7ca096b33662	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	a35e3e7d-3739-4ef7-8f0f-82d42fb5f2b0	0	20	t	86487daa-007f-40ff-882a-398b6a01a48d	\N
c188cf32-cd6d-44f1-8f7a-09d119bad954	\N	idp-email-verification	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	86487daa-007f-40ff-882a-398b6a01a48d	2	10	f	\N	\N
0852a6c8-97df-496f-98e3-d0535f418b11	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	86487daa-007f-40ff-882a-398b6a01a48d	2	20	t	d7afbc1c-28c7-49b6-97b3-c60b6326a456	\N
a9e8ed7d-862c-486b-8063-dbcbb161263c	\N	idp-username-password-form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	d7afbc1c-28c7-49b6-97b3-c60b6326a456	0	10	f	\N	\N
7bd04ae9-cda0-4d5e-ae0c-e1b212c772e1	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	d7afbc1c-28c7-49b6-97b3-c60b6326a456	1	20	t	9249a086-7f60-4df4-9c16-f3ce00e90b7f	\N
aa1a6832-2d94-433e-babb-49e114e7599d	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	9249a086-7f60-4df4-9c16-f3ce00e90b7f	0	10	f	\N	\N
c4890eb7-ca19-4de9-a32e-5274707763cc	\N	auth-otp-form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	9249a086-7f60-4df4-9c16-f3ce00e90b7f	0	20	f	\N	\N
737369d8-e19c-4f71-b537-50f24efa67f0	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e840cd3c-8a7c-408b-a232-efd488fbe293	1	50	t	80908599-a467-4cf9-8012-ec2107a06c43	\N
263b90b5-92a1-4e07-8d4d-4807714616f2	\N	conditional-user-configured	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	80908599-a467-4cf9-8012-ec2107a06c43	0	10	f	\N	\N
4b7c655c-5c0b-4a17-9515-3b3902e70dbf	\N	idp-add-organization-member	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	80908599-a467-4cf9-8012-ec2107a06c43	0	20	f	\N	\N
7cbffceb-6a96-437e-aef8-04c32c528857	\N	http-basic-authenticator	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	aa2061bf-c242-4e12-b6e5-76d0edccf942	0	10	f	\N	\N
b59ad65a-848d-4dc5-9fb3-d91fbc2363fb	\N	docker-http-basic-authenticator	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	9da04634-988c-46aa-b2cd-a32be33ac91f	0	10	f	\N	\N
\.


--
-- Data for Name: authentication_flow; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.authentication_flow (id, alias, description, realm_id, provider_id, top_level, built_in) FROM stdin;
78446504-0b4c-4af0-ad14-873219332369	browser	Browser based authentication	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
6a0c9aae-e4fb-4ecf-a50b-fc02b8749fc5	forms	Username, password, otp and other auth forms.	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
bd34f85f-b155-4939-b810-b54e6e23ff6c	Browser - Conditional OTP	Flow to determine if the OTP is required for the authentication	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
e0d57b8a-61c5-4c6d-82fc-1d1c3b1a3cf6	direct grant	OpenID Connect Resource Owner Grant	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
10ba598f-97f5-4cc3-9283-ac80a4a0409f	Direct Grant - Conditional OTP	Flow to determine if the OTP is required for the authentication	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
c999d09a-a3df-4fc0-9363-f53186cbf71a	registration	Registration flow	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
40416775-8135-47fb-9c8e-f5dddea32564	registration form	Registration form	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	form-flow	f	t
2557231a-a634-4c1d-a7f1-1992cfa00924	reset credentials	Reset credentials for a user if they forgot their password or something	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
f0bd1252-4fed-403d-9b57-cc6f5f6b2919	Reset - Conditional OTP	Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
d4128574-8dfe-42ed-b9d9-d032451a6828	clients	Base authentication for clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	client-flow	t	t
c13a3512-6b0e-4198-8f81-6dacf5d80d57	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
8be42ca2-de81-4aca-b724-cf94f23121e0	User creation or linking	Flow for the existing/non-existing user alternatives	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
52dba704-3f7c-41bf-8a66-542dccdfd5fb	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
847ce45c-1160-4f98-9318-0fd4726b0d61	Account verification options	Method with which to verity the existing account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
c40fff6a-c627-4e2a-9aba-b9d77a49cd16	Verify Existing Account by Re-authentication	Reauthentication of existing account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
24149f98-8b6a-4949-a8da-7457a0b142e9	First broker login - Conditional OTP	Flow to determine if the OTP is required for the authentication	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	f	t
1612f2e8-3660-4f4b-bcf4-1d7b50b125be	saml ecp	SAML ECP Profile Authentication Flow	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
028aa2e6-43d2-4060-829c-72c105543119	docker auth	Used by Docker clients to authenticate against the IDP	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	basic-flow	t	t
3ac63505-a8ac-4176-815a-fa38d513c145	browser	Browser based authentication	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
1a94692c-8ceb-49b6-b83d-e7a7d3da2846	forms	Username, password, otp and other auth forms.	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
4e5e913f-a5ff-4732-abe6-82c049177507	Browser - Conditional OTP	Flow to determine if the OTP is required for the authentication	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
c9c7dc62-565e-42d6-b76b-aa29d5efa43e	Organization	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
33d7a1d3-48de-49a9-a040-d77f751a0523	Browser - Conditional Organization	Flow to determine if the organization identity-first login is to be used	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
adabb682-8fe5-4142-a1ce-59c7e8219470	direct grant	OpenID Connect Resource Owner Grant	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
74b03ad4-8bc9-49c5-be44-fb37762ea98d	Direct Grant - Conditional OTP	Flow to determine if the OTP is required for the authentication	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
2bda16cd-a2ee-4899-9281-01120e271f39	registration	Registration flow	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
e2ee3021-280a-4456-8491-636c795b619f	registration form	Registration form	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	form-flow	f	t
042e46e8-c183-4d61-8b08-ba48ceb00fd1	reset credentials	Reset credentials for a user if they forgot their password or something	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
88959bdc-83f8-4464-a7ab-aafcb248b9cc	Reset - Conditional OTP	Flow to determine if the OTP should be reset or not. Set to REQUIRED to force.	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
65c30146-5469-4da5-a010-dfad5eee7fdd	clients	Base authentication for clients	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	client-flow	t	t
e840cd3c-8a7c-408b-a232-efd488fbe293	first broker login	Actions taken after first broker login with identity provider account, which is not yet linked to any Keycloak account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
8ede821f-1184-4f20-ab6b-2bd013740234	User creation or linking	Flow for the existing/non-existing user alternatives	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
a35e3e7d-3739-4ef7-8f0f-82d42fb5f2b0	Handle Existing Account	Handle what to do if there is existing account with same email/username like authenticated identity provider	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
86487daa-007f-40ff-882a-398b6a01a48d	Account verification options	Method with which to verity the existing account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
d7afbc1c-28c7-49b6-97b3-c60b6326a456	Verify Existing Account by Re-authentication	Reauthentication of existing account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
9249a086-7f60-4df4-9c16-f3ce00e90b7f	First broker login - Conditional OTP	Flow to determine if the OTP is required for the authentication	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
80908599-a467-4cf9-8012-ec2107a06c43	First Broker Login - Conditional Organization	Flow to determine if the authenticator that adds organization members is to be used	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	f	t
aa2061bf-c242-4e12-b6e5-76d0edccf942	saml ecp	SAML ECP Profile Authentication Flow	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
9da04634-988c-46aa-b2cd-a32be33ac91f	docker auth	Used by Docker clients to authenticate against the IDP	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	basic-flow	t	t
\.


--
-- Data for Name: authenticator_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.authenticator_config (id, alias, realm_id) FROM stdin;
8a2f1bb9-2f49-4651-b9d4-5e0856344577	review profile config	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f
f6608271-7113-4483-9a37-ba9fd9cb86f8	create unique user config	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f
ec7cb439-8b32-44c7-a450-70c400f165ba	review profile config	1fd1d65f-fda3-4eb2-9093-366dc2f226ac
2f9d6abc-6145-435a-8aee-0dbdb041358e	create unique user config	1fd1d65f-fda3-4eb2-9093-366dc2f226ac
\.


--
-- Data for Name: authenticator_config_entry; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.authenticator_config_entry (authenticator_id, value, name) FROM stdin;
8a2f1bb9-2f49-4651-b9d4-5e0856344577	missing	update.profile.on.first.login
f6608271-7113-4483-9a37-ba9fd9cb86f8	false	require.password.update.after.registration
2f9d6abc-6145-435a-8aee-0dbdb041358e	false	require.password.update.after.registration
ec7cb439-8b32-44c7-a450-70c400f165ba	missing	update.profile.on.first.login
\.


--
-- Data for Name: broker_link; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.broker_link (identity_provider, storage_provider_id, realm_id, broker_user_id, broker_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: client; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client (id, enabled, full_scope_allowed, client_id, not_before, public_client, secret, base_url, bearer_only, management_url, surrogate_auth_required, realm_id, protocol, node_rereg_timeout, frontchannel_logout, consent_required, name, service_accounts_enabled, client_authenticator_type, root_url, description, registration_token, standard_flow_enabled, implicit_flow_enabled, direct_access_grants_enabled, always_display_in_console) FROM stdin;
da4c211e-5148-4471-8884-d95420b88548	t	f	master-realm	0	f	\N	\N	t	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	0	f	f	master Realm	f	client-secret	\N	\N	\N	t	f	f	f
6125bc74-bea8-40b9-b320-d88778d34fba	t	f	account	0	t	\N	/realms/master/account/	f	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	openid-connect	0	f	f	${client_account}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
66a0b273-0636-4348-8af9-896341a374ed	t	f	account-console	0	t	\N	/realms/master/account/	f	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	openid-connect	0	f	f	${client_account-console}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
80a65571-abe9-4b9f-8140-be9172234c3c	t	f	broker	0	f	\N	\N	t	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	t	t	security-admin-console	0	t	\N	/admin/master/console/	f	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	${authAdminUrl}	\N	\N	t	f	f	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	t	t	admin-cli	0	t	\N	\N	f	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t	f
e927bf1e-34ba-4182-9815-66a5c84b7a23	t	f	Test-realm	0	f	\N	\N	t	\N	f	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	0	f	f	Test Realm	f	client-secret	\N	\N	\N	t	f	f	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	f	realm-management	0	f	\N	\N	t	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_realm-management}	f	client-secret	\N	\N	\N	t	f	f	f
6f74340e-b12f-46cb-b362-f59b37cc8930	t	f	account	0	t	\N	/realms/Test/account/	f	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_account}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	t	f	account-console	0	t	\N	/realms/Test/account/	f	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_account-console}	f	client-secret	${authBaseUrl}	\N	\N	t	f	f	f
28fedf47-b677-460d-99e8-b30a2f48ef23	t	f	broker	0	f	\N	\N	t	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_broker}	f	client-secret	\N	\N	\N	t	f	f	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	t	t	security-admin-console	0	t	\N	/admin/Test/console/	f	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_security-admin-console}	f	client-secret	${authAdminUrl}	\N	\N	t	f	f	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	t	t	admin-cli	0	t	\N	\N	f	\N	f	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	openid-connect	0	f	f	${client_admin-cli}	f	client-secret	\N	\N	\N	f	f	t	f
\.


--
-- Data for Name: client_attributes; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_attributes (client_id, name, value) FROM stdin;
6125bc74-bea8-40b9-b320-d88778d34fba	post.logout.redirect.uris	+
66a0b273-0636-4348-8af9-896341a374ed	post.logout.redirect.uris	+
66a0b273-0636-4348-8af9-896341a374ed	pkce.code.challenge.method	S256
1fec1117-a310-4f9d-9373-1c76e8b7d64b	post.logout.redirect.uris	+
1fec1117-a310-4f9d-9373-1c76e8b7d64b	pkce.code.challenge.method	S256
1fec1117-a310-4f9d-9373-1c76e8b7d64b	client.use.lightweight.access.token.enabled	true
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	client.use.lightweight.access.token.enabled	true
6f74340e-b12f-46cb-b362-f59b37cc8930	post.logout.redirect.uris	+
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	post.logout.redirect.uris	+
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	pkce.code.challenge.method	S256
09c0b19b-3328-44b8-b0d5-983e6b4b358e	post.logout.redirect.uris	+
09c0b19b-3328-44b8-b0d5-983e6b4b358e	pkce.code.challenge.method	S256
09c0b19b-3328-44b8-b0d5-983e6b4b358e	client.use.lightweight.access.token.enabled	true
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	client.use.lightweight.access.token.enabled	true
\.


--
-- Data for Name: client_auth_flow_bindings; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_auth_flow_bindings (client_id, flow_id, binding_name) FROM stdin;
\.


--
-- Data for Name: client_initial_access; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_initial_access (id, realm_id, "timestamp", expiration, count, remaining_count) FROM stdin;
\.


--
-- Data for Name: client_node_registrations; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_node_registrations (client_id, value, name) FROM stdin;
\.


--
-- Data for Name: client_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_scope (id, name, realm_id, description, protocol) FROM stdin;
15324f7e-f5bc-4e29-900e-464a36a51ac8	offline_access	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect built-in scope: offline_access	openid-connect
d00a9373-d558-43ef-b0b3-d197537acf26	role_list	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	SAML role list	saml
756440de-7d62-4f2b-aa1e-21612b4d747b	saml_organization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	Organization Membership	saml
9189c2f5-780a-4347-89aa-bb708ea0b969	profile	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect built-in scope: profile	openid-connect
9d0e598a-91b2-4e09-a240-de8f8b0bb287	email	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect built-in scope: email	openid-connect
c2b49809-d53a-449d-8918-828b07ed42d5	address	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect built-in scope: address	openid-connect
cf19844b-ca5d-4e1f-942a-0c24bb75018b	phone	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect built-in scope: phone	openid-connect
aa2067c1-393a-476e-914a-cbeef275af20	roles	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect scope for add user roles to the access token	openid-connect
7ceeed05-cc86-4863-986c-f99a80c79c23	web-origins	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect scope for add allowed web origins to the access token	openid-connect
c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	microprofile-jwt	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	Microprofile - JWT built-in scope	openid-connect
426c7d8c-da42-4f46-8f7c-3dca6582a547	acr	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect scope for add acr (authentication context class reference) to the token	openid-connect
e8d6020e-1b3d-4b1d-a390-4697c8b54ade	basic	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	OpenID Connect scope for add all basic claims to the token	openid-connect
af569dea-9156-434a-903b-cda6ab43876a	organization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	Additional claims about the organization a subject belongs to	openid-connect
be2edb6c-df16-4e4e-b393-fc338fdc6ad4	offline_access	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect built-in scope: offline_access	openid-connect
db5dbc08-6e34-41a1-8dcc-04bbc89e55f9	role_list	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	SAML role list	saml
2318ad8c-852e-4888-8aaf-b43e86ab596b	saml_organization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	Organization Membership	saml
de37461f-0e67-4f6e-86c8-df54cab2d27a	profile	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect built-in scope: profile	openid-connect
2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	email	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect built-in scope: email	openid-connect
af60348c-4eb0-40a0-a6c2-d7884782dc55	address	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect built-in scope: address	openid-connect
cd449209-e0f7-4a55-877c-f7bb7e96e233	phone	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect built-in scope: phone	openid-connect
1e9464fe-767e-42bf-a6b7-d023f9db9fdb	roles	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect scope for add user roles to the access token	openid-connect
5dd2a98c-7928-4e6f-a3f1-7840459a74b1	web-origins	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect scope for add allowed web origins to the access token	openid-connect
4c688c12-0165-4ec5-9745-67cf86f04be4	microprofile-jwt	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	Microprofile - JWT built-in scope	openid-connect
e2faba26-586b-4646-b495-db2ca9ae59e3	acr	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect scope for add acr (authentication context class reference) to the token	openid-connect
726bbb5a-7140-46b4-9812-e5bcf6065075	basic	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	OpenID Connect scope for add all basic claims to the token	openid-connect
a2ce9b1d-8529-4870-b8d5-52d47d668a24	organization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	Additional claims about the organization a subject belongs to	openid-connect
\.


--
-- Data for Name: client_scope_attributes; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_scope_attributes (scope_id, value, name) FROM stdin;
15324f7e-f5bc-4e29-900e-464a36a51ac8	true	display.on.consent.screen
15324f7e-f5bc-4e29-900e-464a36a51ac8	${offlineAccessScopeConsentText}	consent.screen.text
d00a9373-d558-43ef-b0b3-d197537acf26	true	display.on.consent.screen
d00a9373-d558-43ef-b0b3-d197537acf26	${samlRoleListScopeConsentText}	consent.screen.text
756440de-7d62-4f2b-aa1e-21612b4d747b	false	display.on.consent.screen
9189c2f5-780a-4347-89aa-bb708ea0b969	true	display.on.consent.screen
9189c2f5-780a-4347-89aa-bb708ea0b969	${profileScopeConsentText}	consent.screen.text
9189c2f5-780a-4347-89aa-bb708ea0b969	true	include.in.token.scope
9d0e598a-91b2-4e09-a240-de8f8b0bb287	true	display.on.consent.screen
9d0e598a-91b2-4e09-a240-de8f8b0bb287	${emailScopeConsentText}	consent.screen.text
9d0e598a-91b2-4e09-a240-de8f8b0bb287	true	include.in.token.scope
c2b49809-d53a-449d-8918-828b07ed42d5	true	display.on.consent.screen
c2b49809-d53a-449d-8918-828b07ed42d5	${addressScopeConsentText}	consent.screen.text
c2b49809-d53a-449d-8918-828b07ed42d5	true	include.in.token.scope
cf19844b-ca5d-4e1f-942a-0c24bb75018b	true	display.on.consent.screen
cf19844b-ca5d-4e1f-942a-0c24bb75018b	${phoneScopeConsentText}	consent.screen.text
cf19844b-ca5d-4e1f-942a-0c24bb75018b	true	include.in.token.scope
aa2067c1-393a-476e-914a-cbeef275af20	true	display.on.consent.screen
aa2067c1-393a-476e-914a-cbeef275af20	${rolesScopeConsentText}	consent.screen.text
aa2067c1-393a-476e-914a-cbeef275af20	false	include.in.token.scope
7ceeed05-cc86-4863-986c-f99a80c79c23	false	display.on.consent.screen
7ceeed05-cc86-4863-986c-f99a80c79c23		consent.screen.text
7ceeed05-cc86-4863-986c-f99a80c79c23	false	include.in.token.scope
c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	false	display.on.consent.screen
c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	true	include.in.token.scope
426c7d8c-da42-4f46-8f7c-3dca6582a547	false	display.on.consent.screen
426c7d8c-da42-4f46-8f7c-3dca6582a547	false	include.in.token.scope
e8d6020e-1b3d-4b1d-a390-4697c8b54ade	false	display.on.consent.screen
e8d6020e-1b3d-4b1d-a390-4697c8b54ade	false	include.in.token.scope
af569dea-9156-434a-903b-cda6ab43876a	true	display.on.consent.screen
af569dea-9156-434a-903b-cda6ab43876a	${organizationScopeConsentText}	consent.screen.text
af569dea-9156-434a-903b-cda6ab43876a	true	include.in.token.scope
be2edb6c-df16-4e4e-b393-fc338fdc6ad4	true	display.on.consent.screen
be2edb6c-df16-4e4e-b393-fc338fdc6ad4	${offlineAccessScopeConsentText}	consent.screen.text
db5dbc08-6e34-41a1-8dcc-04bbc89e55f9	true	display.on.consent.screen
db5dbc08-6e34-41a1-8dcc-04bbc89e55f9	${samlRoleListScopeConsentText}	consent.screen.text
2318ad8c-852e-4888-8aaf-b43e86ab596b	false	display.on.consent.screen
de37461f-0e67-4f6e-86c8-df54cab2d27a	true	display.on.consent.screen
de37461f-0e67-4f6e-86c8-df54cab2d27a	${profileScopeConsentText}	consent.screen.text
de37461f-0e67-4f6e-86c8-df54cab2d27a	true	include.in.token.scope
2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	true	display.on.consent.screen
2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	${emailScopeConsentText}	consent.screen.text
2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	true	include.in.token.scope
af60348c-4eb0-40a0-a6c2-d7884782dc55	true	display.on.consent.screen
af60348c-4eb0-40a0-a6c2-d7884782dc55	${addressScopeConsentText}	consent.screen.text
af60348c-4eb0-40a0-a6c2-d7884782dc55	true	include.in.token.scope
cd449209-e0f7-4a55-877c-f7bb7e96e233	true	display.on.consent.screen
cd449209-e0f7-4a55-877c-f7bb7e96e233	${phoneScopeConsentText}	consent.screen.text
cd449209-e0f7-4a55-877c-f7bb7e96e233	true	include.in.token.scope
1e9464fe-767e-42bf-a6b7-d023f9db9fdb	true	display.on.consent.screen
1e9464fe-767e-42bf-a6b7-d023f9db9fdb	${rolesScopeConsentText}	consent.screen.text
1e9464fe-767e-42bf-a6b7-d023f9db9fdb	false	include.in.token.scope
5dd2a98c-7928-4e6f-a3f1-7840459a74b1	false	display.on.consent.screen
5dd2a98c-7928-4e6f-a3f1-7840459a74b1		consent.screen.text
5dd2a98c-7928-4e6f-a3f1-7840459a74b1	false	include.in.token.scope
4c688c12-0165-4ec5-9745-67cf86f04be4	false	display.on.consent.screen
4c688c12-0165-4ec5-9745-67cf86f04be4	true	include.in.token.scope
e2faba26-586b-4646-b495-db2ca9ae59e3	false	display.on.consent.screen
e2faba26-586b-4646-b495-db2ca9ae59e3	false	include.in.token.scope
726bbb5a-7140-46b4-9812-e5bcf6065075	false	display.on.consent.screen
726bbb5a-7140-46b4-9812-e5bcf6065075	false	include.in.token.scope
a2ce9b1d-8529-4870-b8d5-52d47d668a24	true	display.on.consent.screen
a2ce9b1d-8529-4870-b8d5-52d47d668a24	${organizationScopeConsentText}	consent.screen.text
a2ce9b1d-8529-4870-b8d5-52d47d668a24	true	include.in.token.scope
\.


--
-- Data for Name: client_scope_client; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_scope_client (client_id, scope_id, default_scope) FROM stdin;
6125bc74-bea8-40b9-b320-d88778d34fba	9189c2f5-780a-4347-89aa-bb708ea0b969	t
6125bc74-bea8-40b9-b320-d88778d34fba	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
6125bc74-bea8-40b9-b320-d88778d34fba	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
6125bc74-bea8-40b9-b320-d88778d34fba	aa2067c1-393a-476e-914a-cbeef275af20	t
6125bc74-bea8-40b9-b320-d88778d34fba	7ceeed05-cc86-4863-986c-f99a80c79c23	t
6125bc74-bea8-40b9-b320-d88778d34fba	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
6125bc74-bea8-40b9-b320-d88778d34fba	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
6125bc74-bea8-40b9-b320-d88778d34fba	c2b49809-d53a-449d-8918-828b07ed42d5	f
6125bc74-bea8-40b9-b320-d88778d34fba	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
6125bc74-bea8-40b9-b320-d88778d34fba	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
6125bc74-bea8-40b9-b320-d88778d34fba	af569dea-9156-434a-903b-cda6ab43876a	f
66a0b273-0636-4348-8af9-896341a374ed	9189c2f5-780a-4347-89aa-bb708ea0b969	t
66a0b273-0636-4348-8af9-896341a374ed	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
66a0b273-0636-4348-8af9-896341a374ed	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
66a0b273-0636-4348-8af9-896341a374ed	aa2067c1-393a-476e-914a-cbeef275af20	t
66a0b273-0636-4348-8af9-896341a374ed	7ceeed05-cc86-4863-986c-f99a80c79c23	t
66a0b273-0636-4348-8af9-896341a374ed	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
66a0b273-0636-4348-8af9-896341a374ed	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
66a0b273-0636-4348-8af9-896341a374ed	c2b49809-d53a-449d-8918-828b07ed42d5	f
66a0b273-0636-4348-8af9-896341a374ed	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
66a0b273-0636-4348-8af9-896341a374ed	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
66a0b273-0636-4348-8af9-896341a374ed	af569dea-9156-434a-903b-cda6ab43876a	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	9189c2f5-780a-4347-89aa-bb708ea0b969	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	aa2067c1-393a-476e-914a-cbeef275af20	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	7ceeed05-cc86-4863-986c-f99a80c79c23	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	c2b49809-d53a-449d-8918-828b07ed42d5	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
3c31ac7b-aa86-4802-a8e7-d1186d1b772f	af569dea-9156-434a-903b-cda6ab43876a	f
80a65571-abe9-4b9f-8140-be9172234c3c	9189c2f5-780a-4347-89aa-bb708ea0b969	t
80a65571-abe9-4b9f-8140-be9172234c3c	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
80a65571-abe9-4b9f-8140-be9172234c3c	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
80a65571-abe9-4b9f-8140-be9172234c3c	aa2067c1-393a-476e-914a-cbeef275af20	t
80a65571-abe9-4b9f-8140-be9172234c3c	7ceeed05-cc86-4863-986c-f99a80c79c23	t
80a65571-abe9-4b9f-8140-be9172234c3c	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
80a65571-abe9-4b9f-8140-be9172234c3c	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
80a65571-abe9-4b9f-8140-be9172234c3c	c2b49809-d53a-449d-8918-828b07ed42d5	f
80a65571-abe9-4b9f-8140-be9172234c3c	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
80a65571-abe9-4b9f-8140-be9172234c3c	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
80a65571-abe9-4b9f-8140-be9172234c3c	af569dea-9156-434a-903b-cda6ab43876a	f
da4c211e-5148-4471-8884-d95420b88548	9189c2f5-780a-4347-89aa-bb708ea0b969	t
da4c211e-5148-4471-8884-d95420b88548	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
da4c211e-5148-4471-8884-d95420b88548	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
da4c211e-5148-4471-8884-d95420b88548	aa2067c1-393a-476e-914a-cbeef275af20	t
da4c211e-5148-4471-8884-d95420b88548	7ceeed05-cc86-4863-986c-f99a80c79c23	t
da4c211e-5148-4471-8884-d95420b88548	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
da4c211e-5148-4471-8884-d95420b88548	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
da4c211e-5148-4471-8884-d95420b88548	c2b49809-d53a-449d-8918-828b07ed42d5	f
da4c211e-5148-4471-8884-d95420b88548	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
da4c211e-5148-4471-8884-d95420b88548	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
da4c211e-5148-4471-8884-d95420b88548	af569dea-9156-434a-903b-cda6ab43876a	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	9189c2f5-780a-4347-89aa-bb708ea0b969	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	aa2067c1-393a-476e-914a-cbeef275af20	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	7ceeed05-cc86-4863-986c-f99a80c79c23	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
1fec1117-a310-4f9d-9373-1c76e8b7d64b	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	c2b49809-d53a-449d-8918-828b07ed42d5	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
1fec1117-a310-4f9d-9373-1c76e8b7d64b	af569dea-9156-434a-903b-cda6ab43876a	f
6f74340e-b12f-46cb-b362-f59b37cc8930	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
6f74340e-b12f-46cb-b362-f59b37cc8930	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
6f74340e-b12f-46cb-b362-f59b37cc8930	e2faba26-586b-4646-b495-db2ca9ae59e3	t
6f74340e-b12f-46cb-b362-f59b37cc8930	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
6f74340e-b12f-46cb-b362-f59b37cc8930	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
6f74340e-b12f-46cb-b362-f59b37cc8930	726bbb5a-7140-46b4-9812-e5bcf6065075	t
6f74340e-b12f-46cb-b362-f59b37cc8930	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
6f74340e-b12f-46cb-b362-f59b37cc8930	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
6f74340e-b12f-46cb-b362-f59b37cc8930	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
6f74340e-b12f-46cb-b362-f59b37cc8930	4c688c12-0165-4ec5-9745-67cf86f04be4	f
6f74340e-b12f-46cb-b362-f59b37cc8930	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	e2faba26-586b-4646-b495-db2ca9ae59e3	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	726bbb5a-7140-46b4-9812-e5bcf6065075	t
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	4c688c12-0165-4ec5-9745-67cf86f04be4	f
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	e2faba26-586b-4646-b495-db2ca9ae59e3	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	726bbb5a-7140-46b4-9812-e5bcf6065075	t
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	4c688c12-0165-4ec5-9745-67cf86f04be4	f
d7bdbb78-403d-49b7-9ad8-3d23e35ae394	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
28fedf47-b677-460d-99e8-b30a2f48ef23	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
28fedf47-b677-460d-99e8-b30a2f48ef23	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
28fedf47-b677-460d-99e8-b30a2f48ef23	e2faba26-586b-4646-b495-db2ca9ae59e3	t
28fedf47-b677-460d-99e8-b30a2f48ef23	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
28fedf47-b677-460d-99e8-b30a2f48ef23	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
28fedf47-b677-460d-99e8-b30a2f48ef23	726bbb5a-7140-46b4-9812-e5bcf6065075	t
28fedf47-b677-460d-99e8-b30a2f48ef23	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
28fedf47-b677-460d-99e8-b30a2f48ef23	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
28fedf47-b677-460d-99e8-b30a2f48ef23	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
28fedf47-b677-460d-99e8-b30a2f48ef23	4c688c12-0165-4ec5-9745-67cf86f04be4	f
28fedf47-b677-460d-99e8-b30a2f48ef23	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	e2faba26-586b-4646-b495-db2ca9ae59e3	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	726bbb5a-7140-46b4-9812-e5bcf6065075	t
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	4c688c12-0165-4ec5-9745-67cf86f04be4	f
34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	e2faba26-586b-4646-b495-db2ca9ae59e3	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	726bbb5a-7140-46b4-9812-e5bcf6065075	t
09c0b19b-3328-44b8-b0d5-983e6b4b358e	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	4c688c12-0165-4ec5-9745-67cf86f04be4	f
09c0b19b-3328-44b8-b0d5-983e6b4b358e	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
\.


--
-- Data for Name: client_scope_role_mapping; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.client_scope_role_mapping (scope_id, role_id) FROM stdin;
15324f7e-f5bc-4e29-900e-464a36a51ac8	67e69687-c5af-422f-9c6d-dd9ca6064817
be2edb6c-df16-4e4e-b393-fc338fdc6ad4	092ee966-a8ce-4aa8-b6af-ab9aef05d48d
\.


--
-- Data for Name: component; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.component (id, name, parent_id, provider_id, provider_type, realm_id, sub_type) FROM stdin;
705f7161-dc55-4c06-97da-de2e6260d6e1	Trusted Hosts	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
e8725112-70c2-4090-9561-032175444f16	Consent Required	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
3e73040a-0022-418d-a450-71ef4181d583	Full Scope Disabled	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
6ae8d288-76f5-484e-907b-ca240bc9bf5a	Max Clients Limit	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
5c306996-c6ee-47be-8c80-b3800f8e9d1a	Allowed Protocol Mapper Types	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
eb096b8c-c978-475d-8bcf-64a6ab9243f1	Allowed Client Scopes	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	anonymous
fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	Allowed Protocol Mapper Types	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	authenticated
86acfe1d-90ae-4147-96ba-eadfbb2be8fa	Allowed Client Scopes	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	authenticated
36751a6c-f6ad-42c5-adca-329863761074	rsa-generated	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	rsa-generated	org.keycloak.keys.KeyProvider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N
e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	rsa-enc-generated	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	rsa-enc-generated	org.keycloak.keys.KeyProvider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N
efe117ab-2372-4020-8548-93e5d42e8c24	hmac-generated-hs512	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	hmac-generated	org.keycloak.keys.KeyProvider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N
0c9d7124-a7ee-4d80-81ff-ffd79d07b57a	aes-generated	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	aes-generated	org.keycloak.keys.KeyProvider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N
eb5f6de1-53e2-4a02-8be7-2408bf9a33c8	\N	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	declarative-user-profile	org.keycloak.userprofile.UserProfileProvider	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N
72c359ae-f6f7-48e9-bbfa-fd4c1e52fbe4	rsa-generated	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	rsa-generated	org.keycloak.keys.KeyProvider	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N
5bce13d6-b708-4acc-b1f4-83e098bf2fca	rsa-enc-generated	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	rsa-enc-generated	org.keycloak.keys.KeyProvider	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N
c40d46f3-9ba9-437f-a727-43878173db11	hmac-generated-hs512	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	hmac-generated	org.keycloak.keys.KeyProvider	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N
c243058e-238f-43aa-acc3-a8b8c3844d11	aes-generated	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	aes-generated	org.keycloak.keys.KeyProvider	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N
8ceba1c9-f84f-4b73-8e6f-61c98b68632e	Trusted Hosts	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	trusted-hosts	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
6ced2e1b-c7cc-4922-82d9-ae095e9d52e1	Consent Required	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	consent-required	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
f4a4c531-fb86-4431-bb57-90bf57abd7f7	Full Scope Disabled	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	scope	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
c066b552-006f-4654-9abd-61acd6c75880	Max Clients Limit	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	max-clients	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
5f81fb52-e5e5-4f83-a42b-112ca5597e81	Allowed Protocol Mapper Types	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
73530d75-fc08-4087-9eaa-ce6ae020a161	Allowed Client Scopes	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	anonymous
76cdf380-c062-49c6-9616-e1bc7f99f223	Allowed Protocol Mapper Types	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	allowed-protocol-mappers	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	authenticated
d9f5fd3f-6283-4e90-8e5d-f5dfdb2a6fe9	Allowed Client Scopes	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	allowed-client-templates	org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	authenticated
\.


--
-- Data for Name: component_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.component_config (id, component_id, name, value) FROM stdin;
88d4ece1-0b56-4479-883e-5b2b8f57a104	6ae8d288-76f5-484e-907b-ca240bc9bf5a	max-clients	200
b12dec8c-7af7-43f3-9bef-f29cc0a1e525	eb096b8c-c978-475d-8bcf-64a6ab9243f1	allow-default-scopes	true
a0dfb981-3407-4f15-8a06-7b55e0e6c253	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	saml-user-attribute-mapper
3ce192f5-d213-4801-aca5-43a7baaa611b	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
7504264f-4c00-41e3-b657-41e050451e7e	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	oidc-full-name-mapper
8511e5fe-412a-496a-b414-600e73cb68cc	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
d06b8404-b887-4f0b-8ae4-4a1d389b0bf9	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	saml-user-property-mapper
ee36ce6b-7ff8-4e3e-8df6-a80c4ff60a1d	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	saml-role-list-mapper
9f1b7963-7b0d-4a50-ac40-d035b4748687	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	oidc-address-mapper
29142beb-4ad8-4a66-8c8c-fcb1d3412531	fd2c86a2-2007-4a32-b92e-a2f30e0a99a8	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
b039ef8a-61ec-4d7a-bb4f-ac041f10b0ac	705f7161-dc55-4c06-97da-de2e6260d6e1	host-sending-registration-request-must-match	true
811253a9-ccad-45c6-a57a-1acf2659729e	705f7161-dc55-4c06-97da-de2e6260d6e1	client-uris-must-match	true
e1d139ea-70cd-42d1-95f7-b76117bfed5f	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	oidc-full-name-mapper
ecb7bc18-a457-4935-92c0-a53f3a43b0c2	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	saml-user-attribute-mapper
0ae66fde-ae50-4442-80ed-5a645502ecbe	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
22e29fb6-a2d3-451e-aaa4-78d82b5c4679	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	oidc-address-mapper
b09d12f0-4d13-43d7-bded-51f68a9b912f	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	saml-user-property-mapper
c40e7174-34ce-4f54-be88-b76fda5df1a4	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	saml-role-list-mapper
eaac9ddf-1f83-4b0e-980b-b4c95bb3d7ef	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
d5ba5b6d-c958-4c8d-91e6-aaddfcf1f99a	5c306996-c6ee-47be-8c80-b3800f8e9d1a	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
4ce3bf27-61c2-40e4-a4ea-d05a24ee1f40	86acfe1d-90ae-4147-96ba-eadfbb2be8fa	allow-default-scopes	true
633513dd-54c5-4237-baec-377241f5fe43	0c9d7124-a7ee-4d80-81ff-ffd79d07b57a	secret	T-6tLTTtU9t09rZld0cppg
94cb5dd6-89ab-46bc-9f66-e64f93bc2cb6	0c9d7124-a7ee-4d80-81ff-ffd79d07b57a	kid	1f736cb0-09b0-4dcd-bc06-a373beed0f1b
6606b51a-94a4-43bc-8abe-0c3a15685525	0c9d7124-a7ee-4d80-81ff-ffd79d07b57a	priority	100
23b0d670-35a9-4eb8-be1b-ea5c8914f649	efe117ab-2372-4020-8548-93e5d42e8c24	kid	3f4ad90c-5414-46b1-ae58-960ff8c0dbc3
aab477e7-f7b0-48b0-a7a8-8041d42fda4c	efe117ab-2372-4020-8548-93e5d42e8c24	algorithm	HS512
6de4da09-553c-4fa3-a98e-bbcb9cc88b6e	efe117ab-2372-4020-8548-93e5d42e8c24	secret	HlPgW7RnV9QzP8PSFmULOoVdGYo2T2HWwSvPOyx8Sh2jafOOYarnUiB10PXu3gNroJ1Xbe_YMAl1LsU95EcWfo5pgTggtKmKHKxgaKyBCNgvSCfincj9ltPMIKfAvy5vAsRK1EEPxq1c-vYyQquiCZUWmLQHaom7gmREdEUSO6c
69a510c9-31cd-4189-bf4f-d0f48d82e85e	efe117ab-2372-4020-8548-93e5d42e8c24	priority	100
6e5a80c1-11fb-4b55-9328-1457b7b29aba	36751a6c-f6ad-42c5-adca-329863761074	certificate	MIICmzCCAYMCBgGSkdw0KzANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQxMDE1MjAyNDQwWhcNMzQxMDE1MjAyNjIwWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2V2uw8J72+jOfZhe01tbz5LS4po9ZWwZvIRoLb/cu7mv/NEhizJW0Q9YLmEVgZ7IFwKL++XCcyBjszcu9H4YSnV/1qEbqS4DdRM0YqguMP4/fD8u1Zrq4ofsRq5FlR4PC89gSy0b0aZXd1vhqh2lDtp3xvixkID7CtEyMv0fGkfLDy/G+ARIC7YLQEMbOHK4TeEzze4g0xqWbG4imPcFjh2VebgTsSWLsJyWeNODOyZNGsl8Xfc5/tiYVCRtOfeKNSnf95dGKIwNGY3shNEmde+Pc5Fjs44p0+xGlxaZ/8kskqdhXFTb9OaGL1ImbhdaWLKzrDaW14dzRK1rQfsEBAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAEAIE7if+mHCR5lJco3xqMIXFSAydRCGZ7sesItNUZGWQ9PF4htNCfS+PNtXcyX1gWyENbfEkEt2LlviBT1VjastIeTKYho3rmWzv6LHN9mZpT763p8vQSL0UhW3p79uL3C9WluGiCjRHp3jjYSptIwYplxr9IZuK6hUL0WK6pfcMXMOrWPPnggRaiMIR7S+CPYRte9FLNdnOPSLn8t9UvXWPXZAeEw//PEkzXnFwjqiSG520gl0I3RVor1mFd/S5XsJtgsgP+CNxN9nE1QXYOzxMHcOsj9ssf2e+E3Lmv3T5mLRgx+fwDCj88zxXmOWLlNtFHfPnN4ac+/GgPYDdY0=
fd25c497-0f42-4c10-9626-592f9a4be8a1	36751a6c-f6ad-42c5-adca-329863761074	privateKey	MIIEowIBAAKCAQEAtldrsPCe9vozn2YXtNbW8+S0uKaPWVsGbyEaC2/3Lu5r/zRIYsyVtEPWC5hFYGeyBcCi/vlwnMgY7M3LvR+GEp1f9ahG6kuA3UTNGKoLjD+P3w/LtWa6uKH7EauRZUeDwvPYEstG9GmV3db4aodpQ7ad8b4sZCA+wrRMjL9HxpHyw8vxvgESAu2C0BDGzhyuE3hM83uINMalmxuIpj3BY4dlXm4E7Eli7CclnjTgzsmTRrJfF33Of7YmFQkbTn3ijUp3/eXRiiMDRmN7ITRJnXvj3ORY7OOKdPsRpcWmf/JLJKnYVxU2/Tmhi9SJm4XWliys6w2lteHc0Sta0H7BAQIDAQABAoIBAAfacclSAby4J7lHqcF4h9NDEEwMI2wpLRij87XWpY4kR2s7TptPvaphChLfhOxrJuoTwwlph6G/BgDL98iOVyVN2SRQ0jYU2KjfBdjYOQ1aLvl/2gmW8jeRxWkcSzOyHfELdMzRa73K3uEqOTKIYL6hesG+y7VnxKA46PueYOpiy+/fiZZriHbPrinwnvuO3Z7OLoWdSK+cATLbWnk61DlMh01kzVTt9OpCdDDSlr3yJ3ltLk1qiatiXtJr35H+s9X43W4Cz94MGHqKE8quPw6gRErGB41MLbtELIJoiMWYtmm+7nZdNtT2HQv/Rx0sKlw9sMxmFy4vYxiZxUKCidkCgYEA426MbYKQWzMGBaRhN+9Iaza/Or+bniy7LY2XhfIfejKLzYMwPa6FWFgVAo0c16m2U6U/9lomBReMREL4sTjs1OWg+eAKZLHlj9g/MJ4JIP9P5iF6HH11+ghuDHZ5HEYJRzg5sPMWACb9w8McOzoqpxoC5uyYOn2ClGU9JMFZLikCgYEAzT7qps1tQWjIDcYo++eJ0V0ZFpMT0lL8zhQzIv67wLNedwr+lpiVLVRKJWZYXfzN6z4Hw6RWNAEM3/I4gK3u8FJbGz8zLEg39iIZg3ra6q8rq3eoporR4d+vspw1kPW4Q/hJubCkN6A32jEJMlk2rW+TFDMYTRh2v2Go9HjZJxkCgYA7TNfQtfptzSAE2JeAviNj0SKLbupkk8U6W3Dmu/r5IbTSISKy8o5SOqU/xQuAMAAaTzweP+Mp8LniEpRFoVIfMMCIZqJPHxN8LiZLxukacXejyZbNVuksCIapOTra5GgG6eIhAUD7SS9hm74As2nrqByZmZcXqSIjD0KiEsfuAQKBgQCcIJklC61pjUho2e2BOe8nePdFqdnxKzmtlcYUf8vY2Vkpmw5xBl6sHatNad4cmNsXcJc9ZrxAUPA3Rq1ejXDuFOfDAT9vFvyi2euojYML9PZ2N87t6Tmg5aRkbNl+jLx/z9ZdT5aLze/OpXCGgUDLi81JF1kMBGkISkTYuzkMuQKBgAYqN6+FL3nzLlA53zB4yEZK0yZd39Zjo1NzV2+/quyuyl7QXY71TWq1CXj1ZdIPkwfJJu02QOQlvW3P7mx2ivTXpZFeqU4+gB9o8euqeEcWm1XFqJDiIvRR+Dx0wZiUSIMrmFAHnwjy5ibtOY2RtzuBcBCBcGHnIzKuepGlVrei
a94340a1-9d31-4b5d-8140-64e954c12943	36751a6c-f6ad-42c5-adca-329863761074	priority	100
917c2bde-57a2-4091-ac6b-8569a3533f85	36751a6c-f6ad-42c5-adca-329863761074	keyUse	SIG
0fbf0892-63be-4687-a463-e802b0632d14	eb5f6de1-53e2-4a02-8be7-2408bf9a33c8	kc.user.profile.config	{"attributes":[{"name":"username","displayName":"${username}","validations":{"length":{"min":3,"max":255},"username-prohibited-characters":{},"up-username-not-idn-homograph":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"email","displayName":"${email}","validations":{"email":{},"length":{"max":255}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"firstName","displayName":"${firstName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false},{"name":"lastName","displayName":"${lastName}","validations":{"length":{"max":255},"person-name-prohibited-characters":{}},"permissions":{"view":["admin","user"],"edit":["admin","user"]},"multivalued":false}],"groups":[{"name":"user-metadata","displayHeader":"User metadata","displayDescription":"Attributes, which refer to user metadata"}]}
b24bedd5-f1bc-4ab6-bc46-93409156b58b	e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	priority	100
6e7c170d-dd5b-4083-a4ed-dd91aa91cef5	e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	certificate	MIICmzCCAYMCBgGSkdw0sjANBgkqhkiG9w0BAQsFADARMQ8wDQYDVQQDDAZtYXN0ZXIwHhcNMjQxMDE1MjAyNDQwWhcNMzQxMDE1MjAyNjIwWjARMQ8wDQYDVQQDDAZtYXN0ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC1VlKQSgzcaelC3XHIJCPxOpAxmPufAozBJ8WRNsvXXhrFKCX4LjXO9J4aH5S5WPX4tR8ghYN0ueTRjI6oXcRKLOIf6QOE+rh0Hfqqk3+a7/YB5IpJV+ujXXdeXQSvdMvnn93IdE8puZDiDfSG2Lt389BO6eHj3GIoPHzXocjwq6VjIWcMplXfMvk4euV08AuZCcy1g5gg/wMmgzKy6rM4gqYsRxjfPn2N5m3o4WeBI3eJDDbKnrR7IglvIBIP53EoeYwRsesI43cM6XO4js2hcEAxUkkcKnilkrISjqPebjIe9X1Hg3Tmbetg/UH9bDeWEzUvGr9pfi8HizCXdIKJAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAK7lPT+Y04XaO1VuGtWSnI5dPEOT2FJFHsYynSBQ/NvWGzpUePox6pHr+ow3gnIwd2OAZUe2DUgAmYhPApquKWPL8j+gdDNKmcMgvOAtzIhHeNwuF2AJNHZf5mn6R0LsMqYVX3Lk89VThMuZjwnJEFrI9b+IyQ+c+aYRmjyVnChjSV0r+NqJcaygPelzJCmJ9bqxjaYJGTbCcdYSVigjVi5n/DP1uu4wPtNTTgKrDYqkC3iZZeIEs6X4OCxhStR6t7ZWMkqR9bX/SDQId9vJo61Eoxjkh3KZ0gIeb5yNVdlnhhmuonH+0wcQwnEh/8G62BK0Ak2chTTQsgX4Xas2BWs=
0d8a29a8-3054-45c8-bd8d-039ae4f88376	e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	privateKey	MIIEogIBAAKCAQEAtVZSkEoM3GnpQt1xyCQj8TqQMZj7nwKMwSfFkTbL114axSgl+C41zvSeGh+UuVj1+LUfIIWDdLnk0YyOqF3ESiziH+kDhPq4dB36qpN/mu/2AeSKSVfro113Xl0Er3TL55/dyHRPKbmQ4g30hti7d/PQTunh49xiKDx816HI8KulYyFnDKZV3zL5OHrldPALmQnMtYOYIP8DJoMysuqzOIKmLEcY3z59jeZt6OFngSN3iQw2yp60eyIJbyASD+dxKHmMEbHrCON3DOlzuI7NoXBAMVJJHCp4pZKyEo6j3m4yHvV9R4N05m3rYP1B/Ww3lhM1Lxq/aX4vB4swl3SCiQIDAQABAoIBAASXqdIhKfe4D/IDUTMgJS/iC45SAUda5W0r4G9Hy7xJ1BQ7qtCA/RhfbhSbyaSzCdGxZpcognaFkbOz41YEv+if/98Og+oNfnfkXXmN8DygiKKuIsluOlfCEXiYkvqNku9sB04hEfMs0axD7bYvjXnheRxShIfEiFDcDU5ZuNDNgSHT0LH9AWrQ7N0UmU1TvehzPOVWwAjjaRc69xVJesPkqw/c4kY9TO/N/+UKEmksnMwfvyb+HBjYdxdZRFCy9tZCjSrIG9pmXyU1E3q1DibCpoJ4iTS+DKgPOLbsXRibSoRA9GOjfgxO0pqjCK7R4NofhaD325V0mikq5XBzb40CgYEA2w+nWIGOgu5PJ4FuKJ7QETnZpdm0OFRsdkCVn2K4YSEh3YGTygEJz+FRtJFfe3wAdqz5pmZibDzxtgJF4gK6/e/2GlkH1ZhvTcpTbi9ajUmZFutWIbBBSLSNXAdqTGM72azHT9l7FgQY7Catn+Br5XCxa5W4VZLpwIVKMw1hA1UCgYEA0+o3TlA4ML8YO61WowM7vlfDFtgps4e2c/d21t6+SRaAXxWsnbRHi6/AsLLIw6/Wns24rTKRfGvpTt2CDYHGTIyNjuYByXmE7YS4iujxfLfO8eHqKGGTcgQ+F78qqZ5hfELpBG0WQxMXgeAZD2BbLitW86tuvp83rUgO2IuZamUCgYA8jOghw7XjpQGGFvWfDr7OdCIgALwa8eMFELcK1lvGpUTaGE4EgSL4LfzKn4A3/r+WDhv3jcdYycO6Hoi4fy62sFRjVgafWMIzS2CiTT6HXTeOqUAmkbSJ5zZHoNkWAjvx4Bs7jA7EuB83bz2AuqS4R90SstC//prUF0O6NtGA/QKBgDJho8Z1ofZM6Fj/y/IziZemS9Z5i+iH4mPNuK47BKhhtiFlCMXxn3ThUwFvb/W+L1tP85ERza70BOLgHNRTPy7h16HaoyAgSO8jN7Cm0wrgtE2jdUUmdaSMx6pjo6Px6KFfUwDfYoSN3G/fNHYIZYUjfqet4UVmmxkSYZ0wC0hVAoGAOVtRt1yhAgp1yqlqobkKUQcqZFUcFcbDtHuXlT8t3zPkMp6eL8kbyINDg4GkNBhqVh1c7ciWWrIM7syWCEf5F1oEeZS5dadXPHfug1QoQ4KHvYS+E6UcbkuLTOYcfFLaY8dF7bhOcciACoNhdJwDdWPi1vRCLRQ+zNQ5GWX2fro=
373bf5cc-a086-4dff-85d6-ad2ab0ecd41c	e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	keyUse	ENC
f710696d-170f-487c-932c-feb3ddc0a458	e16f462f-5ce0-4fdf-85c3-34e0fe7f618e	algorithm	RSA-OAEP
33a9b6c2-2675-4612-a2db-e5346b74c7aa	5bce13d6-b708-4acc-b1f4-83e098bf2fca	priority	100
8ea57f80-f00a-478b-88f4-477476a4a3ba	5bce13d6-b708-4acc-b1f4-83e098bf2fca	algorithm	RSA-OAEP
68828e45-5d17-4481-90e2-ed1628c62293	5bce13d6-b708-4acc-b1f4-83e098bf2fca	privateKey	MIIEogIBAAKCAQEAid8XEwAWodjTZ8iQfOtX5Wqq/lOfVJCEMYQalEqLoGcNEw55WaAky2j3+eSfQIYs33MhPTHx/U01hZZtHMny+aZa7JeJhgZRE3b/H4XdFRwrBFY8x+IX/PFKFNVECNwWlXEp5x6/GixbwtP/V0ePXB4PNS1Xrc2zWswy6DbAuQLmIT5CvSfQEq1rfXm+WfPDoIW3BHcPFEVBMBqu5rGKdte70hQthzXWEF+yLCxKbnDMg1gwbRQCzS/e10Acbue0yniH2ftAKNFWl5oJC9xWLCl7ahNwFKsQ5ULRMPcdJYosgOWYxB8AHezmcDbaxnENy4RPRp1kVZb5e2xpnP0FBwIDAQABAoIBAA6QqmPf+QQdH2xR5G3GARGj/K+EjwsEf2qpvZMX8vs9l8SBHXHJ+MkibDwSmn5bDmeGxqar3Zg4bWSQ+TL25LvaBrYC5kzp4uvPAPHIFwyRXrwFDkPBj24x4XUk+JyE/7/G5jnb5i1yLTl+YvXKAgulw06HXUFnv0Bi3SfqDN8elxW0iYG11qSQtTQcpXBR+Y9CZBaDlp6hWIxPYIiUKW9V20ryFDC5cEGYe7nf7Zvl3Pcksn/EbdmDggVSkrFFTy3fEY/5cmbVLHvkVUaquNG12ZKLhSQiFGW4ZPGh6ptG8R19uwa/AoA3I8zsssquyQ9oiIFfRhgOQ1SVJpRMmZkCgYEAvhULCqnU2ez5GEU2EWLRzGXE//Bc4cjkITM2mAkivkw9NzBSSBOyTTHXYMcfrzpzaKdRNyHE5jftpK/hd60o+b5R45sMIce3SsUULItUBAm6K9/Vo5H3QLjaz2voydF59kN8wg4ACH3kl43s7ELNOcj0jh2X4aRUtnHC2CapflkCgYEAua7swR24TGC0UKzV0ctR4/Tjrl/SVBxUTmxf+0iKC7DCK2rRCGHCw3SpqHC6UV6RcfJo72ePnHJNuauNv/VFNmQgAcYZBDoupfiKXbtEp/nGIyLkM0dBjsVrLkTPwQvK+qy/np7TNrvoI4vXDysBvKvZuizkxRtUEd2y/bD/8l8CgYBLvlDnD+O8bzyXWkUASpN1UnxczGgGpKmbPTAdB07r669dBYlUJV0ge6Lqco6CodUJN9saD//JCTJONLOwn7S7SAaTnt4Hu/Ci/8NZOK/i6AlioFAeXPTcuoyeqM5bVXi3FA9ruG50882aQrjNMJVc2GHzG4HBLV2AUfalcUqLCQKBgEX3oyDVyReGrQtlRSDLo2zpX03ar4+gKShv7+7pE5N6JIBlvKSS6efqsu9UovB8WQP92wqzFEtYSu92tHArxMvNCL6CXfTY07EYqVLOeP1uwfmFcUXdSNe6jjueFEbi4bZ5l672nBIY1k1mqT/+7aWhf+aGeiHHvXMJ/iNYKemzAoGAaEP1z3oElZlPJ/vdccsALRLpcsokcP6lH6MeXC8a2OWvlbgL5jgyL+i6hcT0Pmh/c0+xENXMC14gAwp+dsgXrh/P0VfNGpKcSHJfu14M+9ImumZXGF3ji6ayl1Un4ns7FFE5lORisgKcFlsQtedu/wUsLy3jbQoAwH+3D70r7mI=
6a964527-e571-407a-9b59-d7df3b9a6246	5bce13d6-b708-4acc-b1f4-83e098bf2fca	keyUse	ENC
8c37b1a4-b750-4b44-aece-e052608d8be2	5bce13d6-b708-4acc-b1f4-83e098bf2fca	certificate	MIIClzCCAX8CBgGSkd1rVzANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARUZXN0MB4XDTI0MTAxNTIwMjYwMFoXDTM0MTAxNTIwMjc0MFowDzENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAInfFxMAFqHY02fIkHzrV+Vqqv5Tn1SQhDGEGpRKi6BnDRMOeVmgJMto9/nkn0CGLN9zIT0x8f1NNYWWbRzJ8vmmWuyXiYYGURN2/x+F3RUcKwRWPMfiF/zxShTVRAjcFpVxKecevxosW8LT/1dHj1weDzUtV63Ns1rMMug2wLkC5iE+Qr0n0BKta315vlnzw6CFtwR3DxRFQTAaruaxinbXu9IULYc11hBfsiwsSm5wzINYMG0UAs0v3tdAHG7ntMp4h9n7QCjRVpeaCQvcViwpe2oTcBSrEOVC0TD3HSWKLIDlmMQfAB3s5nA22sZxDcuET0adZFWW+XtsaZz9BQcCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAQDkZqqJiIyr5MqR2Eb5P9X05+vvUclxmN9MeekP0H/vZVmOU/xcwBI1ZiTBs+kGfRLOafEoXEpXk7CuAxPcP+kwTjCZ8Stbc3KNSqzZiYfxbil6fTYvwxRrpLY+jcl5v8ZQZ7XoW3cftGyi9Jwwr0d6+96go8+cHOT090GKGteHqWgPqU0HUp+G5y1pG7+LJUsXUWlOvZiGGI9y5OgQgSfYBZm+aflhHYEdOOdd52GibTwqio/e5jd7g3yAzhOJklgPrOL6UPlk6Xllp1/84N9pYv1v+sNq76K6bswlTGh2MI640FeTYgT5t4CcD40wvfiRfHKdy1iun0EMiDCsrDg==
e062738e-f893-4043-9afb-19fd2741f860	72c359ae-f6f7-48e9-bbfa-fd4c1e52fbe4	priority	100
eb0fa542-0039-4c71-ae53-142bc3c8ac67	72c359ae-f6f7-48e9-bbfa-fd4c1e52fbe4	certificate	MIIClzCCAX8CBgGSkd1qqjANBgkqhkiG9w0BAQsFADAPMQ0wCwYDVQQDDARUZXN0MB4XDTI0MTAxNTIwMjYwMFoXDTM0MTAxNTIwMjc0MFowDzENMAsGA1UEAwwEVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMlpNf3N7F9Tf05QV989e4kDaDKYd+CsObyHoQCWp1lE+U2AZkabIvojCRPCpqRVKxhvCUbP/yA69fKt0B8di2GLOCzjd4sbXHAW2xMbJ6C0Tu1WaIaMLvm7hXBoGEo1ScJOnNUtwjPBGtNzD/9yXj4C19VMWcnPF/SY3QQn/K3eUjoktK6EXt62AMs6bswxyX1vIqiaShKbldcCviA1WVoZ2O0eIUP05vvaAa6U/tX5V61VP0DnaedHu9F5hMS95nJG4sLE7r/rGn447h0Xts1jVK+nD6DnCUDE8YPCRpuwc2rTmHEyLjFLGGMQu1B/BN3/Mjtais9/rzpixHYxYQECAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAGZEA7HooQrjJ3QCtcdWcgxZBQmYNNCyKtQdMvk5wHCmf3SwdJOZrwSypypCQpOgR7I7eln5pPJj4Rj8lKT0Q8pE+oyA7kTKKmnCCbaHjgWoYe5dI1oSqeT8ENPnpNpOw6dYUZHVvgHATSUTVDbzOwwkaLPW7khc6BQb+Zii8ytyqIMTj3GyKYV4X6m+ufLhj6TT34jperdvuSpzlFEpa0sVWGT5cwPfhTnvHCPciwhpMFtar/beTbc5K4K2KiRV9S4hEbE74smPul6H/ke2OPTLEg4SB19UQMAdoP/YTNR5DxnHQeGQNTpn92oTquVmC/9sjhOs4qyLJHTv1Ul3Wjw==
f630fd2b-93d9-4aea-9221-197dd43948c7	72c359ae-f6f7-48e9-bbfa-fd4c1e52fbe4	keyUse	SIG
e309b672-2c52-40dc-bb54-ed37da1c999f	72c359ae-f6f7-48e9-bbfa-fd4c1e52fbe4	privateKey	MIIEowIBAAKCAQEAyWk1/c3sX1N/TlBX3z17iQNoMph34Kw5vIehAJanWUT5TYBmRpsi+iMJE8KmpFUrGG8JRs//IDr18q3QHx2LYYs4LON3ixtccBbbExsnoLRO7VZohowu+buFcGgYSjVJwk6c1S3CM8Ea03MP/3JePgLX1UxZyc8X9JjdBCf8rd5SOiS0roRe3rYAyzpuzDHJfW8iqJpKEpuV1wK+IDVZWhnY7R4hQ/Tm+9oBrpT+1flXrVU/QOdp50e70XmExL3mckbiwsTuv+safjjuHRe2zWNUr6cPoOcJQMTxg8JGm7BzatOYcTIuMUsYYxC7UH8E3f8yO1qKz3+vOmLEdjFhAQIDAQABAoIBABjzW6jmtagpeSqDxsmfnYofo0Ir+SMassb+1kcdt/rVvJHenMzqXa7htYzTyZOvU/i26KNJE7CJHVFu5CAL/OmcjDJOC3puwp4azBDV2wGMKgA6JWtlj6bdlW4+DE7vwwS7Ja/oTJffYtSxpa2zcVFP8No6QcqU88FtSRPsEDVJjiCQWZAGNATW13fZ0JFxg4B7HEucWYZcSD5EN6Umb3L3SlKGYjkNqKrV4Hj6FHXLoaOz+7d/Oscq8SgY9SuZp6s6Wi2Gg9rwuAnJj6AJ+taPs4Iarrws9Md9VaI/I5p2hLPMUSV0mCQ3mrisqKJ5nZY06Sz6lVWFwZARjSNQxfECgYEA+ZkvY2kPCQeG0lSB2JFplH8qQAuxspyuwx6SyaPcTKXwZkWKYFgIcvvq8JcxvsqAJcCeYYGLlgsAzPzxu082zO7skp/Jo/C7Jby1EAGyXShi5d4fr3Hs0Hilx+e1B24igjIYa8GvG3rnyziiyEKPKBD5G8gm5t13NGcSyYJ16vsCgYEAzpOi+OKUnSz87i3csEcTuoBEkQF0hF8qNTsic5Sqze5uZlzi8GfpijmUJkZv/GbJuakZmf2S1QvQyCOL84bNayzDtm5ijGSBjUBENkNJQkBlkLC1TWJdHnLgOxIVjhWQqMrh81M294bt6KHPJ1dbctuo+1tUMV/2WJZAeGxV4zMCgYEAin4g+Tv2B8CRYmtZkN0+hBL7UoYqlzyxC7sPH6s4NZ9tgJHdcg/mwEZf2hdKlt6ttETonJnQ5fQ9AYDocFJHyfZYdhMLQ1fzv8CxhqwqV95s4bcaRbMk/5eyBPXgULsfkrZRLplNnCXaL7zBNfUYkda5Il0wmLERz5XRqtYkr7kCgYBfAzqfHJ/cFvgSmJd7oIVrb1maFEBCLf8c0qEK5iMVaofunuRmTHT29Xq1jAov3hsEQMmcsSuav798fhT9ok/S7pjpzKWZCxUnIZr+Fj6YsUPFo/EPsaFAwvdtU+kEG9kYOZBpOSn7+VxtdhbwclaGYo+7ZIs51nhY0GrAuJtcTwKBgClLa6tzSnTX1bL9jKyeoaQkztpV2QgCqZ0LHGaHZmMs4lISKCDEIhp+Ix+cBbLxzkEHWdwO654jQetSLLBMr2utMmB6o+MKAp7j6MYxrbvls3gmKl2676sD58NbkWG8kNAbVdXr8LorT96Zr+ZopQQ3swNOa0USu1lrMhjK1K/o
e9a4c677-e813-4f98-af41-c7bc7b2ceef9	c40d46f3-9ba9-437f-a727-43878173db11	kid	8f21a25e-5417-45b8-9004-eb5d27255cf8
3ce39a7f-f774-4b77-b0e8-79302c7905ca	c40d46f3-9ba9-437f-a727-43878173db11	secret	Cj_-GPttYs_3pXRMonH1Q6N_QT4UdI4fD4t7IJK9SXKjRFItDZ5axYD5S0Rupw1kknzY_ZNWQsuCwVGyc4HSyt0Se8UZGsgu2HcLe8OpBBiQe-QIBXbSBQQTJuVbxV_QVa6j6Iz1Re4fr4nwvjPW8fSJjVvvkBZKM7blalIgsxA
8cf56ad5-5f1e-4282-adf8-0c4b6544ba40	c40d46f3-9ba9-437f-a727-43878173db11	priority	100
199c4a46-caf0-473f-83f2-69301ae007fa	c40d46f3-9ba9-437f-a727-43878173db11	algorithm	HS512
09f6dd54-c247-4723-89d0-5e6aecfe0ef2	c243058e-238f-43aa-acc3-a8b8c3844d11	secret	MsHwZ1hcyFLv1uucaJMDNQ
351c48a9-7e6d-4176-b7f5-f0d192466ee8	c243058e-238f-43aa-acc3-a8b8c3844d11	priority	100
78d17a72-b0d5-4b5e-bd19-5355add93747	c243058e-238f-43aa-acc3-a8b8c3844d11	kid	c3e6227d-740a-4e5c-b469-a1386f82966a
35f95413-b437-4a02-ab8b-924c3e8a477c	d9f5fd3f-6283-4e90-8e5d-f5dfdb2a6fe9	allow-default-scopes	true
ce82fa53-aab7-4707-b99e-9f24107b94b6	73530d75-fc08-4087-9eaa-ce6ae020a161	allow-default-scopes	true
9c1cf9d6-8bdf-4bc4-a063-b3a5d90621c6	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
9b2ea52f-45f5-44eb-9987-23734649e3a6	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	saml-user-attribute-mapper
037d8f1a-5e2e-47ea-8f50-48dc250d61a4	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	oidc-full-name-mapper
585f4643-279c-4d23-b4b0-150f91acd027	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	saml-user-property-mapper
6d71f417-9905-44c2-9739-6068c6d62fef	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
ef1f0c79-87d0-4b70-9efa-6152b5f381e7	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	oidc-address-mapper
3e64ef30-5f9d-4b65-b49f-61efdcc0ec96	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
890eba4e-6db6-4e87-bbfd-c220cfc7e635	5f81fb52-e5e5-4f83-a42b-112ca5597e81	allowed-protocol-mapper-types	saml-role-list-mapper
1ca44fe0-9602-4fb4-aa83-39fbf12d0004	c066b552-006f-4654-9abd-61acd6c75880	max-clients	200
bd291e37-131f-43e8-90b7-3af28a9a8261	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	saml-role-list-mapper
55f37dbd-9cf6-4f92-80b7-79159a0a437a	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	saml-user-property-mapper
053ccf08-ff44-4440-bbe7-a6374e74f876	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	oidc-usermodel-attribute-mapper
68419c16-e732-42c6-8aa1-18d3f66a25fd	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	oidc-sha256-pairwise-sub-mapper
b47d5d04-a095-41cd-adac-855d8b7f716d	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	saml-user-attribute-mapper
0ac3cad8-d078-4f75-bccf-7fa9f5d929a0	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	oidc-full-name-mapper
2e9a4d47-31cf-49bd-950f-ad90e9c27217	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	oidc-usermodel-property-mapper
f0e8b9e4-86dc-4ee4-b2be-e291e3fb9a8f	76cdf380-c062-49c6-9616-e1bc7f99f223	allowed-protocol-mapper-types	oidc-address-mapper
1f610bf9-c226-4a39-b8ab-565b1ad6b2d8	8ceba1c9-f84f-4b73-8e6f-61c98b68632e	client-uris-must-match	true
890e45a9-1835-4b52-a567-ac4ae4657fcf	8ceba1c9-f84f-4b73-8e6f-61c98b68632e	host-sending-registration-request-must-match	true
\.


--
-- Data for Name: composite_role; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.composite_role (composite, child_role) FROM stdin;
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	73a8cfb4-2f8d-4e71-a383-c59f23015994
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	4909c761-7ef5-45a8-a0be-9bac3def2c41
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	013bd164-f10b-427b-8e9a-a78859c73961
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	0b2db8fe-8417-4628-8767-becbb6ed2ce1
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	084baff1-aee8-45a3-9f78-d0458f13537c
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	bcb932fb-8121-4a18-8c4c-0104d624abef
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	52cee13d-2af2-4349-b998-e2b164f904cf
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	00d339a9-9eae-4325-84d4-77720a3cd90d
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	dcc09017-7a5d-45b5-920a-f3b7c8d39e50
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	d06e4a89-5287-4b66-a263-83e185aea651
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	13ca6cd6-31d6-4292-99e2-a79d640c7fd2
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	6de04d44-1c75-4f4d-a501-beae243ecc9c
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	07c25ed1-c2ac-41f7-9226-6a167848f8b3
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	b695512d-9f72-4234-9a93-4331f4cea609
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	38b81844-dd2e-4027-92da-e90e2b97f7a9
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	e22a7524-f314-45bc-bf27-dabf0a6e98b0
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	b05d9795-f2f4-4959-971c-c75619037108
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	59eab1ac-e8f9-4a1f-8a9d-a677db0f01db
084baff1-aee8-45a3-9f78-d0458f13537c	e22a7524-f314-45bc-bf27-dabf0a6e98b0
0b2db8fe-8417-4628-8767-becbb6ed2ce1	38b81844-dd2e-4027-92da-e90e2b97f7a9
0b2db8fe-8417-4628-8767-becbb6ed2ce1	59eab1ac-e8f9-4a1f-8a9d-a677db0f01db
1300e97a-2599-431d-8169-937df66ace29	a0e86062-51e5-47b2-bafd-c1305fdf7b1a
1300e97a-2599-431d-8169-937df66ace29	c3612af0-a78d-4863-bc60-cfee5b0471c1
c3612af0-a78d-4863-bc60-cfee5b0471c1	7adff7f4-d0eb-47b2-b7b4-a7c4d437bf81
4603ece7-68b0-4063-b18e-487dc31f79c7	5d97954d-865f-4f37-97b4-87f62a604dc7
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	5154abe9-e90f-44ca-ba88-e1c0df330570
1300e97a-2599-431d-8169-937df66ace29	67e69687-c5af-422f-9c6d-dd9ca6064817
1300e97a-2599-431d-8169-937df66ace29	251e2a5f-279a-4f24-a4a9-84ecb1afc201
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	5afa69c0-39b4-437e-9fd9-62bc2bd3a8ac
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	0a8e0d55-bc6b-4a24-8d1a-d7b9ce8cfeca
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	697727aa-0941-4221-a764-8455d785113a
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	efde6b3d-bd27-40c7-bb7a-77f1e53ae027
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	be558d96-d932-49e2-bdf0-bed1cb62f195
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	89c75bb6-e100-4aa2-a01b-24ff61532325
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	40298bbb-de9e-4773-9556-672e334fb790
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	48658c00-7874-4629-a47e-f2a810e5c73d
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	006beb79-4f32-4d27-a1c7-6e7208bda9fa
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	0c129943-2559-4c17-bd40-d4c2fd0b849e
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	5f1473be-13e6-4c35-9877-ccb645cabe2c
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	aaaaed08-fd2f-44dd-834d-87ed8362eb6c
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	f85a8f5c-dfe8-4c61-b2d0-23a8d0cf9642
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	7281a701-8a2e-4e5e-8097-f2196824dfbd
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	88e1a2d8-d44d-4324-a266-21ae8bae06ea
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	1bb4ab62-5767-460b-bdfb-544ff862ac2c
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	1a15ebf6-77d9-4111-bd0b-6db91bbb793b
697727aa-0941-4221-a764-8455d785113a	1a15ebf6-77d9-4111-bd0b-6db91bbb793b
697727aa-0941-4221-a764-8455d785113a	7281a701-8a2e-4e5e-8097-f2196824dfbd
efde6b3d-bd27-40c7-bb7a-77f1e53ae027	88e1a2d8-d44d-4324-a266-21ae8bae06ea
13628d05-9caf-480c-ae1c-92ea26de42b1	12f21043-1b94-4d7c-a025-00dbd116a903
13628d05-9caf-480c-ae1c-92ea26de42b1	60e4c13b-fba2-4c49-a17f-d606f0595e9a
13628d05-9caf-480c-ae1c-92ea26de42b1	f26c857f-0a8f-4112-8b0c-cefa11978f2b
13628d05-9caf-480c-ae1c-92ea26de42b1	4025a7c7-b45c-4478-8da1-6e046124a4ef
13628d05-9caf-480c-ae1c-92ea26de42b1	daf5d3a9-cef3-41d8-b4e3-e6ebe5d7bfa1
13628d05-9caf-480c-ae1c-92ea26de42b1	3bb70329-f2bd-4800-bd67-654ab12a9bc6
13628d05-9caf-480c-ae1c-92ea26de42b1	316c8c11-5140-45dc-9790-6f262c7a92f2
13628d05-9caf-480c-ae1c-92ea26de42b1	8382deaa-a5f7-42e4-815b-460b09931bbf
13628d05-9caf-480c-ae1c-92ea26de42b1	792be8d1-a9a3-4746-8985-ca265f0a1d90
13628d05-9caf-480c-ae1c-92ea26de42b1	994af3d5-88c3-4abc-9d25-67e0ac50fe06
13628d05-9caf-480c-ae1c-92ea26de42b1	a3110636-4295-4e5d-aacd-09625d2e446a
13628d05-9caf-480c-ae1c-92ea26de42b1	8d47f7ec-68c8-4ee1-8d2c-9bd9c120eeba
13628d05-9caf-480c-ae1c-92ea26de42b1	2e73f013-7426-4021-baaf-2023c2bd4b52
13628d05-9caf-480c-ae1c-92ea26de42b1	2ad3a054-c1a8-4b78-8a82-6a9469cae5d3
13628d05-9caf-480c-ae1c-92ea26de42b1	7fb645d9-8a53-456f-8ea9-a2cabc80dac3
13628d05-9caf-480c-ae1c-92ea26de42b1	6274cab9-6eab-42fa-aabd-bac08d5309f4
13628d05-9caf-480c-ae1c-92ea26de42b1	3641a812-b9e4-4822-95d4-eea7d8810ba0
3c4a339d-6f51-4bd0-89ae-6df6717752b1	a2a94e10-852a-4beb-abd9-c56db1904bba
4025a7c7-b45c-4478-8da1-6e046124a4ef	7fb645d9-8a53-456f-8ea9-a2cabc80dac3
f26c857f-0a8f-4112-8b0c-cefa11978f2b	2ad3a054-c1a8-4b78-8a82-6a9469cae5d3
f26c857f-0a8f-4112-8b0c-cefa11978f2b	3641a812-b9e4-4822-95d4-eea7d8810ba0
3c4a339d-6f51-4bd0-89ae-6df6717752b1	3371bb12-52d1-4542-a96e-0a9dac54e424
3371bb12-52d1-4542-a96e-0a9dac54e424	4ccbdbd2-b97d-4a37-8173-5dda28f12750
8dbf782d-4c54-4083-92f5-0055148ffeb9	7ca13251-2fdc-4a27-9318-c5db26e0a813
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	53e36238-93ce-41e5-a98e-98bc18d89700
13628d05-9caf-480c-ae1c-92ea26de42b1	cca7428b-0082-4284-9ce3-fe103d6daaf7
3c4a339d-6f51-4bd0-89ae-6df6717752b1	092ee966-a8ce-4aa8-b6af-ab9aef05d48d
3c4a339d-6f51-4bd0-89ae-6df6717752b1	f1be31ec-7c7b-46b1-93b2-d67a7371ca29
\.


--
-- Data for Name: credential; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.credential (id, salt, type, user_id, created_date, user_label, secret_data, credential_data, priority) FROM stdin;
9263b490-3186-4039-b7ce-7a6468f3fd1c	\N	password	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8	1729024506659	My password	{"value":"fXeLLxQT3jXVF3mV1l7UBGCMopTvYR+IpTZx2+zR5lM=","salt":"3lIhl2mmnjgJaRjCL+QSww==","additionalParameters":{}}	{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}	10
24c0961d-3671-46b6-9698-a91d7059d3f2	\N	password	d5b2a49e-edef-49c1-961f-5d4e562a7659	1729025130718	My password	{"value":"F3HTH8JW078ZT+FDIhMSu8HcoGaCKVCqGOmZSmUybwU=","salt":"eh0N4Oo+vtdtJuR2CYLo4w==","additionalParameters":{}}	{"hashIterations":5,"algorithm":"argon2","additionalParameters":{"hashLength":["32"],"memory":["7168"],"type":["id"],"version":["1.3"],"parallelism":["1"]}}	10
\.


--
-- Data for Name: databasechangelog; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.databasechangelog (id, author, filename, dateexecuted, orderexecuted, exectype, md5sum, description, comments, tag, liquibase, contexts, labels, deployment_id) FROM stdin;
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/jpa-changelog-1.0.0.Final.xml	2024-10-15 20:26:14.753294	1	EXECUTED	9:6f1016664e21e16d26517a4418f5e3df	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	4.29.1	\N	\N	9023974276
1.0.0.Final-KEYCLOAK-5461	sthorger@redhat.com	META-INF/db2-jpa-changelog-1.0.0.Final.xml	2024-10-15 20:26:14.769482	2	MARK_RAN	9:828775b1596a07d1200ba1d49e5e3941	createTable tableName=APPLICATION_DEFAULT_ROLES; createTable tableName=CLIENT; createTable tableName=CLIENT_SESSION; createTable tableName=CLIENT_SESSION_ROLE; createTable tableName=COMPOSITE_ROLE; createTable tableName=CREDENTIAL; createTable tab...		\N	4.29.1	\N	\N	9023974276
1.1.0.Beta1	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Beta1.xml	2024-10-15 20:26:14.821837	3	EXECUTED	9:5f090e44a7d595883c1fb61f4b41fd38	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=CLIENT_ATTRIBUTES; createTable tableName=CLIENT_SESSION_NOTE; createTable tableName=APP_NODE_REGISTRATIONS; addColumn table...		\N	4.29.1	\N	\N	9023974276
1.1.0.Final	sthorger@redhat.com	META-INF/jpa-changelog-1.1.0.Final.xml	2024-10-15 20:26:14.828367	4	EXECUTED	9:c07e577387a3d2c04d1adc9aaad8730e	renameColumn newColumnName=EVENT_TIME, oldColumnName=TIME, tableName=EVENT_ENTITY		\N	4.29.1	\N	\N	9023974276
1.2.0.Beta1	psilva@redhat.com	META-INF/jpa-changelog-1.2.0.Beta1.xml	2024-10-15 20:26:14.954487	5	EXECUTED	9:b68ce996c655922dbcd2fe6b6ae72686	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	4.29.1	\N	\N	9023974276
1.2.0.Beta1	psilva@redhat.com	META-INF/db2-jpa-changelog-1.2.0.Beta1.xml	2024-10-15 20:26:14.960096	6	MARK_RAN	9:543b5c9989f024fe35c6f6c5a97de88e	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION; createTable tableName=PROTOCOL_MAPPER; createTable tableName=PROTOCOL_MAPPER_CONFIG; createTable tableName=...		\N	4.29.1	\N	\N	9023974276
1.2.0.RC1	bburke@redhat.com	META-INF/jpa-changelog-1.2.0.CR1.xml	2024-10-15 20:26:15.068887	7	EXECUTED	9:765afebbe21cf5bbca048e632df38336	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	4.29.1	\N	\N	9023974276
1.2.0.RC1	bburke@redhat.com	META-INF/db2-jpa-changelog-1.2.0.CR1.xml	2024-10-15 20:26:15.075074	8	MARK_RAN	9:db4a145ba11a6fdaefb397f6dbf829a1	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=MIGRATION_MODEL; createTable tableName=IDENTITY_P...		\N	4.29.1	\N	\N	9023974276
1.2.0.Final	keycloak	META-INF/jpa-changelog-1.2.0.Final.xml	2024-10-15 20:26:15.080443	9	EXECUTED	9:9d05c7be10cdb873f8bcb41bc3a8ab23	update tableName=CLIENT; update tableName=CLIENT; update tableName=CLIENT		\N	4.29.1	\N	\N	9023974276
1.3.0	bburke@redhat.com	META-INF/jpa-changelog-1.3.0.xml	2024-10-15 20:26:15.204959	10	EXECUTED	9:18593702353128d53111f9b1ff0b82b8	delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete tableName=USER_SESSION; createTable tableName=ADMI...		\N	4.29.1	\N	\N	9023974276
1.4.0	bburke@redhat.com	META-INF/jpa-changelog-1.4.0.xml	2024-10-15 20:26:15.275673	11	EXECUTED	9:6122efe5f090e41a85c0f1c9e52cbb62	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.29.1	\N	\N	9023974276
1.4.0	bburke@redhat.com	META-INF/db2-jpa-changelog-1.4.0.xml	2024-10-15 20:26:15.280523	12	MARK_RAN	9:e1ff28bf7568451453f844c5d54bb0b5	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.29.1	\N	\N	9023974276
1.5.0	bburke@redhat.com	META-INF/jpa-changelog-1.5.0.xml	2024-10-15 20:26:15.299161	13	EXECUTED	9:7af32cd8957fbc069f796b61217483fd	delete tableName=CLIENT_SESSION_AUTH_STATUS; delete tableName=CLIENT_SESSION_ROLE; delete tableName=CLIENT_SESSION_PROT_MAPPER; delete tableName=CLIENT_SESSION_NOTE; delete tableName=CLIENT_SESSION; delete tableName=USER_SESSION_NOTE; delete table...		\N	4.29.1	\N	\N	9023974276
1.6.1_from15	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2024-10-15 20:26:15.328948	14	EXECUTED	9:6005e15e84714cd83226bf7879f54190	addColumn tableName=REALM; addColumn tableName=KEYCLOAK_ROLE; addColumn tableName=CLIENT; createTable tableName=OFFLINE_USER_SESSION; createTable tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_US_SES_PK2, tableName=...		\N	4.29.1	\N	\N	9023974276
1.6.1_from16-pre	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2024-10-15 20:26:15.331766	15	MARK_RAN	9:bf656f5a2b055d07f314431cae76f06c	delete tableName=OFFLINE_CLIENT_SESSION; delete tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
1.6.1_from16	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2024-10-15 20:26:15.335094	16	MARK_RAN	9:f8dadc9284440469dcf71e25ca6ab99b	dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_US_SES_PK, tableName=OFFLINE_USER_SESSION; dropPrimaryKey constraintName=CONSTRAINT_OFFLINE_CL_SES_PK, tableName=OFFLINE_CLIENT_SESSION; addColumn tableName=OFFLINE_USER_SESSION; update tableName=OF...		\N	4.29.1	\N	\N	9023974276
1.6.1	mposolda@redhat.com	META-INF/jpa-changelog-1.6.1.xml	2024-10-15 20:26:15.338493	17	EXECUTED	9:d41d8cd98f00b204e9800998ecf8427e	empty		\N	4.29.1	\N	\N	9023974276
1.7.0	bburke@redhat.com	META-INF/jpa-changelog-1.7.0.xml	2024-10-15 20:26:15.39094	18	EXECUTED	9:3368ff0be4c2855ee2dd9ca813b38d8e	createTable tableName=KEYCLOAK_GROUP; createTable tableName=GROUP_ROLE_MAPPING; createTable tableName=GROUP_ATTRIBUTE; createTable tableName=USER_GROUP_MEMBERSHIP; createTable tableName=REALM_DEFAULT_GROUPS; addColumn tableName=IDENTITY_PROVIDER; ...		\N	4.29.1	\N	\N	9023974276
1.8.0	mposolda@redhat.com	META-INF/jpa-changelog-1.8.0.xml	2024-10-15 20:26:15.443544	19	EXECUTED	9:8ac2fb5dd030b24c0570a763ed75ed20	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	4.29.1	\N	\N	9023974276
1.8.0-2	keycloak	META-INF/jpa-changelog-1.8.0.xml	2024-10-15 20:26:15.44971	20	EXECUTED	9:f91ddca9b19743db60e3057679810e6c	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	4.29.1	\N	\N	9023974276
26.0.0-33201-org-redirect-url	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.359979	144	EXECUTED	9:4d0e22b0ac68ebe9794fa9cb752ea660	addColumn tableName=ORG		\N	4.29.1	\N	\N	9023974276
1.8.0	mposolda@redhat.com	META-INF/db2-jpa-changelog-1.8.0.xml	2024-10-15 20:26:15.453412	21	MARK_RAN	9:831e82914316dc8a57dc09d755f23c51	addColumn tableName=IDENTITY_PROVIDER; createTable tableName=CLIENT_TEMPLATE; createTable tableName=CLIENT_TEMPLATE_ATTRIBUTES; createTable tableName=TEMPLATE_SCOPE_MAPPING; dropNotNullConstraint columnName=CLIENT_ID, tableName=PROTOCOL_MAPPER; ad...		\N	4.29.1	\N	\N	9023974276
1.8.0-2	keycloak	META-INF/db2-jpa-changelog-1.8.0.xml	2024-10-15 20:26:15.456448	22	MARK_RAN	9:f91ddca9b19743db60e3057679810e6c	dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; update tableName=CREDENTIAL		\N	4.29.1	\N	\N	9023974276
1.9.0	mposolda@redhat.com	META-INF/jpa-changelog-1.9.0.xml	2024-10-15 20:26:15.534484	23	EXECUTED	9:bc3d0f9e823a69dc21e23e94c7a94bb1	update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=REALM; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=REALM; update tableName=REALM; customChange; dr...		\N	4.29.1	\N	\N	9023974276
1.9.1	keycloak	META-INF/jpa-changelog-1.9.1.xml	2024-10-15 20:26:15.541705	24	EXECUTED	9:c9999da42f543575ab790e76439a2679	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=PUBLIC_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	4.29.1	\N	\N	9023974276
1.9.1	keycloak	META-INF/db2-jpa-changelog-1.9.1.xml	2024-10-15 20:26:15.54438	25	MARK_RAN	9:0d6c65c6f58732d81569e77b10ba301d	modifyDataType columnName=PRIVATE_KEY, tableName=REALM; modifyDataType columnName=CERTIFICATE, tableName=REALM		\N	4.29.1	\N	\N	9023974276
1.9.2	keycloak	META-INF/jpa-changelog-1.9.2.xml	2024-10-15 20:26:15.837757	26	EXECUTED	9:fc576660fc016ae53d2d4778d84d86d0	createIndex indexName=IDX_USER_EMAIL, tableName=USER_ENTITY; createIndex indexName=IDX_USER_ROLE_MAPPING, tableName=USER_ROLE_MAPPING; createIndex indexName=IDX_USER_GROUP_MAPPING, tableName=USER_GROUP_MEMBERSHIP; createIndex indexName=IDX_USER_CO...		\N	4.29.1	\N	\N	9023974276
authz-2.0.0	psilva@redhat.com	META-INF/jpa-changelog-authz-2.0.0.xml	2024-10-15 20:26:15.951268	27	EXECUTED	9:43ed6b0da89ff77206289e87eaa9c024	createTable tableName=RESOURCE_SERVER; addPrimaryKey constraintName=CONSTRAINT_FARS, tableName=RESOURCE_SERVER; addUniqueConstraint constraintName=UK_AU8TT6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER; createTable tableName=RESOURCE_SERVER_RESOU...		\N	4.29.1	\N	\N	9023974276
authz-2.5.1	psilva@redhat.com	META-INF/jpa-changelog-authz-2.5.1.xml	2024-10-15 20:26:15.955062	28	EXECUTED	9:44bae577f551b3738740281eceb4ea70	update tableName=RESOURCE_SERVER_POLICY		\N	4.29.1	\N	\N	9023974276
2.1.0-KEYCLOAK-5461	bburke@redhat.com	META-INF/jpa-changelog-2.1.0.xml	2024-10-15 20:26:16.051752	29	EXECUTED	9:bd88e1f833df0420b01e114533aee5e8	createTable tableName=BROKER_LINK; createTable tableName=FED_USER_ATTRIBUTE; createTable tableName=FED_USER_CONSENT; createTable tableName=FED_USER_CONSENT_ROLE; createTable tableName=FED_USER_CONSENT_PROT_MAPPER; createTable tableName=FED_USER_CR...		\N	4.29.1	\N	\N	9023974276
2.2.0	bburke@redhat.com	META-INF/jpa-changelog-2.2.0.xml	2024-10-15 20:26:16.070851	30	EXECUTED	9:a7022af5267f019d020edfe316ef4371	addColumn tableName=ADMIN_EVENT_ENTITY; createTable tableName=CREDENTIAL_ATTRIBUTE; createTable tableName=FED_CREDENTIAL_ATTRIBUTE; modifyDataType columnName=VALUE, tableName=CREDENTIAL; addForeignKeyConstraint baseTableName=FED_CREDENTIAL_ATTRIBU...		\N	4.29.1	\N	\N	9023974276
2.3.0	bburke@redhat.com	META-INF/jpa-changelog-2.3.0.xml	2024-10-15 20:26:16.093903	31	EXECUTED	9:fc155c394040654d6a79227e56f5e25a	createTable tableName=FEDERATED_USER; addPrimaryKey constraintName=CONSTR_FEDERATED_USER, tableName=FEDERATED_USER; dropDefaultValue columnName=TOTP, tableName=USER_ENTITY; dropColumn columnName=TOTP, tableName=USER_ENTITY; addColumn tableName=IDE...		\N	4.29.1	\N	\N	9023974276
2.4.0	bburke@redhat.com	META-INF/jpa-changelog-2.4.0.xml	2024-10-15 20:26:16.098749	32	EXECUTED	9:eac4ffb2a14795e5dc7b426063e54d88	customChange		\N	4.29.1	\N	\N	9023974276
2.5.0	bburke@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2024-10-15 20:26:16.10579	33	EXECUTED	9:54937c05672568c4c64fc9524c1e9462	customChange; modifyDataType columnName=USER_ID, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
2.5.0-unicode-oracle	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2024-10-15 20:26:16.109051	34	MARK_RAN	9:3a32bace77c84d7678d035a7f5a8084e	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	4.29.1	\N	\N	9023974276
2.5.0-unicode-other-dbs	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2024-10-15 20:26:16.144899	35	EXECUTED	9:33d72168746f81f98ae3a1e8e0ca3554	modifyDataType columnName=DESCRIPTION, tableName=AUTHENTICATION_FLOW; modifyDataType columnName=DESCRIPTION, tableName=CLIENT_TEMPLATE; modifyDataType columnName=DESCRIPTION, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=DESCRIPTION,...		\N	4.29.1	\N	\N	9023974276
2.5.0-duplicate-email-support	slawomir@dabek.name	META-INF/jpa-changelog-2.5.0.xml	2024-10-15 20:26:16.152206	36	EXECUTED	9:61b6d3d7a4c0e0024b0c839da283da0c	addColumn tableName=REALM		\N	4.29.1	\N	\N	9023974276
2.5.0-unique-group-names	hmlnarik@redhat.com	META-INF/jpa-changelog-2.5.0.xml	2024-10-15 20:26:16.162979	37	EXECUTED	9:8dcac7bdf7378e7d823cdfddebf72fda	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.29.1	\N	\N	9023974276
2.5.1	bburke@redhat.com	META-INF/jpa-changelog-2.5.1.xml	2024-10-15 20:26:16.169144	38	EXECUTED	9:a2b870802540cb3faa72098db5388af3	addColumn tableName=FED_USER_CONSENT		\N	4.29.1	\N	\N	9023974276
3.0.0	bburke@redhat.com	META-INF/jpa-changelog-3.0.0.xml	2024-10-15 20:26:16.175101	39	EXECUTED	9:132a67499ba24bcc54fb5cbdcfe7e4c0	addColumn tableName=IDENTITY_PROVIDER		\N	4.29.1	\N	\N	9023974276
3.2.0-fix	keycloak	META-INF/jpa-changelog-3.2.0.xml	2024-10-15 20:26:16.177828	40	MARK_RAN	9:938f894c032f5430f2b0fafb1a243462	addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS		\N	4.29.1	\N	\N	9023974276
3.2.0-fix-with-keycloak-5416	keycloak	META-INF/jpa-changelog-3.2.0.xml	2024-10-15 20:26:16.180867	41	MARK_RAN	9:845c332ff1874dc5d35974b0babf3006	dropIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS; addNotNullConstraint columnName=REALM_ID, tableName=CLIENT_INITIAL_ACCESS; createIndex indexName=IDX_CLIENT_INIT_ACC_REALM, tableName=CLIENT_INITIAL_ACCESS		\N	4.29.1	\N	\N	9023974276
3.2.0-fix-offline-sessions	hmlnarik	META-INF/jpa-changelog-3.2.0.xml	2024-10-15 20:26:16.185993	42	EXECUTED	9:fc86359c079781adc577c5a217e4d04c	customChange		\N	4.29.1	\N	\N	9023974276
3.2.0-fixed	keycloak	META-INF/jpa-changelog-3.2.0.xml	2024-10-15 20:26:17.205851	43	EXECUTED	9:59a64800e3c0d09b825f8a3b444fa8f4	addColumn tableName=REALM; dropPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_PK2, tableName=OFFLINE_CLIENT_SESSION; dropColumn columnName=CLIENT_SESSION_ID, tableName=OFFLINE_CLIENT_SESSION; addPrimaryKey constraintName=CONSTRAINT_OFFL_CL_SES_P...		\N	4.29.1	\N	\N	9023974276
3.3.0	keycloak	META-INF/jpa-changelog-3.3.0.xml	2024-10-15 20:26:17.212906	44	EXECUTED	9:d48d6da5c6ccf667807f633fe489ce88	addColumn tableName=USER_ENTITY		\N	4.29.1	\N	\N	9023974276
authz-3.4.0.CR1-resource-server-pk-change-part1	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2024-10-15 20:26:17.22001	45	EXECUTED	9:dde36f7973e80d71fceee683bc5d2951	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_RESOURCE; addColumn tableName=RESOURCE_SERVER_SCOPE		\N	4.29.1	\N	\N	9023974276
authz-3.4.0.CR1-resource-server-pk-change-part2-KEYCLOAK-6095	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2024-10-15 20:26:17.22501	46	EXECUTED	9:b855e9b0a406b34fa323235a0cf4f640	customChange		\N	4.29.1	\N	\N	9023974276
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2024-10-15 20:26:17.227709	47	MARK_RAN	9:51abbacd7b416c50c4421a8cabf7927e	dropIndex indexName=IDX_RES_SERV_POL_RES_SERV, tableName=RESOURCE_SERVER_POLICY; dropIndex indexName=IDX_RES_SRV_RES_RES_SRV, tableName=RESOURCE_SERVER_RESOURCE; dropIndex indexName=IDX_RES_SRV_SCOPE_RES_SRV, tableName=RESOURCE_SERVER_SCOPE		\N	4.29.1	\N	\N	9023974276
authz-3.4.0.CR1-resource-server-pk-change-part3-fixed-nodropindex	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2024-10-15 20:26:17.33695	48	EXECUTED	9:bdc99e567b3398bac83263d375aad143	addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_POLICY; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, tableName=RESOURCE_SERVER_RESOURCE; addNotNullConstraint columnName=RESOURCE_SERVER_CLIENT_ID, ...		\N	4.29.1	\N	\N	9023974276
authn-3.4.0.CR1-refresh-token-max-reuse	glavoie@gmail.com	META-INF/jpa-changelog-authz-3.4.0.CR1.xml	2024-10-15 20:26:17.342946	49	EXECUTED	9:d198654156881c46bfba39abd7769e69	addColumn tableName=REALM		\N	4.29.1	\N	\N	9023974276
3.4.0	keycloak	META-INF/jpa-changelog-3.4.0.xml	2024-10-15 20:26:17.41646	50	EXECUTED	9:cfdd8736332ccdd72c5256ccb42335db	addPrimaryKey constraintName=CONSTRAINT_REALM_DEFAULT_ROLES, tableName=REALM_DEFAULT_ROLES; addPrimaryKey constraintName=CONSTRAINT_COMPOSITE_ROLE, tableName=COMPOSITE_ROLE; addPrimaryKey constraintName=CONSTR_REALM_DEFAULT_GROUPS, tableName=REALM...		\N	4.29.1	\N	\N	9023974276
3.4.0-KEYCLOAK-5230	hmlnarik@redhat.com	META-INF/jpa-changelog-3.4.0.xml	2024-10-15 20:26:17.648901	51	EXECUTED	9:7c84de3d9bd84d7f077607c1a4dcb714	createIndex indexName=IDX_FU_ATTRIBUTE, tableName=FED_USER_ATTRIBUTE; createIndex indexName=IDX_FU_CONSENT, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CONSENT_RU, tableName=FED_USER_CONSENT; createIndex indexName=IDX_FU_CREDENTIAL, t...		\N	4.29.1	\N	\N	9023974276
3.4.1	psilva@redhat.com	META-INF/jpa-changelog-3.4.1.xml	2024-10-15 20:26:17.654719	52	EXECUTED	9:5a6bb36cbefb6a9d6928452c0852af2d	modifyDataType columnName=VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
3.4.2	keycloak	META-INF/jpa-changelog-3.4.2.xml	2024-10-15 20:26:17.658046	53	EXECUTED	9:8f23e334dbc59f82e0a328373ca6ced0	update tableName=REALM		\N	4.29.1	\N	\N	9023974276
3.4.2-KEYCLOAK-5172	mkanis@redhat.com	META-INF/jpa-changelog-3.4.2.xml	2024-10-15 20:26:17.661328	54	EXECUTED	9:9156214268f09d970cdf0e1564d866af	update tableName=CLIENT		\N	4.29.1	\N	\N	9023974276
4.0.0-KEYCLOAK-6335	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2024-10-15 20:26:17.671716	55	EXECUTED	9:db806613b1ed154826c02610b7dbdf74	createTable tableName=CLIENT_AUTH_FLOW_BINDINGS; addPrimaryKey constraintName=C_CLI_FLOW_BIND, tableName=CLIENT_AUTH_FLOW_BINDINGS		\N	4.29.1	\N	\N	9023974276
4.0.0-CLEANUP-UNUSED-TABLE	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2024-10-15 20:26:17.680473	56	EXECUTED	9:229a041fb72d5beac76bb94a5fa709de	dropTable tableName=CLIENT_IDENTITY_PROV_MAPPING		\N	4.29.1	\N	\N	9023974276
4.0.0-KEYCLOAK-6228	bburke@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2024-10-15 20:26:17.728419	57	EXECUTED	9:079899dade9c1e683f26b2aa9ca6ff04	dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; dropNotNullConstraint columnName=CLIENT_ID, tableName=USER_CONSENT; addColumn tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHO...		\N	4.29.1	\N	\N	9023974276
4.0.0-KEYCLOAK-5579-fixed	mposolda@redhat.com	META-INF/jpa-changelog-4.0.0.xml	2024-10-15 20:26:18.013646	58	EXECUTED	9:139b79bcbbfe903bb1c2d2a4dbf001d9	dropForeignKeyConstraint baseTableName=CLIENT_TEMPLATE_ATTRIBUTES, constraintName=FK_CL_TEMPL_ATTR_TEMPL; renameTable newTableName=CLIENT_SCOPE_ATTRIBUTES, oldTableName=CLIENT_TEMPLATE_ATTRIBUTES; renameColumn newColumnName=SCOPE_ID, oldColumnName...		\N	4.29.1	\N	\N	9023974276
authz-4.0.0.CR1	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.CR1.xml	2024-10-15 20:26:18.048321	59	EXECUTED	9:b55738ad889860c625ba2bf483495a04	createTable tableName=RESOURCE_SERVER_PERM_TICKET; addPrimaryKey constraintName=CONSTRAINT_FAPMT, tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRHO213XCX4WNKOG82SSPMT...		\N	4.29.1	\N	\N	9023974276
authz-4.0.0.Beta3	psilva@redhat.com	META-INF/jpa-changelog-authz-4.0.0.Beta3.xml	2024-10-15 20:26:18.055512	60	EXECUTED	9:e0057eac39aa8fc8e09ac6cfa4ae15fe	addColumn tableName=RESOURCE_SERVER_POLICY; addColumn tableName=RESOURCE_SERVER_PERM_TICKET; addForeignKeyConstraint baseTableName=RESOURCE_SERVER_PERM_TICKET, constraintName=FK_FRSRPO2128CX4WNKOG82SSRFY, referencedTableName=RESOURCE_SERVER_POLICY		\N	4.29.1	\N	\N	9023974276
authz-4.2.0.Final	mhajas@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2024-10-15 20:26:18.063679	61	EXECUTED	9:42a33806f3a0443fe0e7feeec821326c	createTable tableName=RESOURCE_URIS; addForeignKeyConstraint baseTableName=RESOURCE_URIS, constraintName=FK_RESOURCE_SERVER_URIS, referencedTableName=RESOURCE_SERVER_RESOURCE; customChange; dropColumn columnName=URI, tableName=RESOURCE_SERVER_RESO...		\N	4.29.1	\N	\N	9023974276
authz-4.2.0.Final-KEYCLOAK-9944	hmlnarik@redhat.com	META-INF/jpa-changelog-authz-4.2.0.Final.xml	2024-10-15 20:26:18.073289	62	EXECUTED	9:9968206fca46eecc1f51db9c024bfe56	addPrimaryKey constraintName=CONSTRAINT_RESOUR_URIS_PK, tableName=RESOURCE_URIS		\N	4.29.1	\N	\N	9023974276
4.2.0-KEYCLOAK-6313	wadahiro@gmail.com	META-INF/jpa-changelog-4.2.0.xml	2024-10-15 20:26:18.078551	63	EXECUTED	9:92143a6daea0a3f3b8f598c97ce55c3d	addColumn tableName=REQUIRED_ACTION_PROVIDER		\N	4.29.1	\N	\N	9023974276
4.3.0-KEYCLOAK-7984	wadahiro@gmail.com	META-INF/jpa-changelog-4.3.0.xml	2024-10-15 20:26:18.081871	64	EXECUTED	9:82bab26a27195d889fb0429003b18f40	update tableName=REQUIRED_ACTION_PROVIDER		\N	4.29.1	\N	\N	9023974276
4.6.0-KEYCLOAK-7950	psilva@redhat.com	META-INF/jpa-changelog-4.6.0.xml	2024-10-15 20:26:18.085176	65	EXECUTED	9:e590c88ddc0b38b0ae4249bbfcb5abc3	update tableName=RESOURCE_SERVER_RESOURCE		\N	4.29.1	\N	\N	9023974276
4.6.0-KEYCLOAK-8377	keycloak	META-INF/jpa-changelog-4.6.0.xml	2024-10-15 20:26:18.122585	66	EXECUTED	9:5c1f475536118dbdc38d5d7977950cc0	createTable tableName=ROLE_ATTRIBUTE; addPrimaryKey constraintName=CONSTRAINT_ROLE_ATTRIBUTE_PK, tableName=ROLE_ATTRIBUTE; addForeignKeyConstraint baseTableName=ROLE_ATTRIBUTE, constraintName=FK_ROLE_ATTRIBUTE_ID, referencedTableName=KEYCLOAK_ROLE...		\N	4.29.1	\N	\N	9023974276
4.6.0-KEYCLOAK-8555	gideonray@gmail.com	META-INF/jpa-changelog-4.6.0.xml	2024-10-15 20:26:18.148588	67	EXECUTED	9:e7c9f5f9c4d67ccbbcc215440c718a17	createIndex indexName=IDX_COMPONENT_PROVIDER_TYPE, tableName=COMPONENT		\N	4.29.1	\N	\N	9023974276
4.7.0-KEYCLOAK-1267	sguilhen@redhat.com	META-INF/jpa-changelog-4.7.0.xml	2024-10-15 20:26:18.155138	68	EXECUTED	9:88e0bfdda924690d6f4e430c53447dd5	addColumn tableName=REALM		\N	4.29.1	\N	\N	9023974276
4.7.0-KEYCLOAK-7275	keycloak	META-INF/jpa-changelog-4.7.0.xml	2024-10-15 20:26:18.185681	69	EXECUTED	9:f53177f137e1c46b6a88c59ec1cb5218	renameColumn newColumnName=CREATED_ON, oldColumnName=LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION; addNotNullConstraint columnName=CREATED_ON, tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_USER_SESSION; customChange; createIn...		\N	4.29.1	\N	\N	9023974276
4.8.0-KEYCLOAK-8835	sguilhen@redhat.com	META-INF/jpa-changelog-4.8.0.xml	2024-10-15 20:26:18.19192	70	EXECUTED	9:a74d33da4dc42a37ec27121580d1459f	addNotNullConstraint columnName=SSO_MAX_LIFESPAN_REMEMBER_ME, tableName=REALM; addNotNullConstraint columnName=SSO_IDLE_TIMEOUT_REMEMBER_ME, tableName=REALM		\N	4.29.1	\N	\N	9023974276
authz-7.0.0-KEYCLOAK-10443	psilva@redhat.com	META-INF/jpa-changelog-authz-7.0.0.xml	2024-10-15 20:26:18.197809	71	EXECUTED	9:fd4ade7b90c3b67fae0bfcfcb42dfb5f	addColumn tableName=RESOURCE_SERVER		\N	4.29.1	\N	\N	9023974276
8.0.0-adding-credential-columns	keycloak	META-INF/jpa-changelog-8.0.0.xml	2024-10-15 20:26:18.205651	72	EXECUTED	9:aa072ad090bbba210d8f18781b8cebf4	addColumn tableName=CREDENTIAL; addColumn tableName=FED_USER_CREDENTIAL		\N	4.29.1	\N	\N	9023974276
8.0.0-updating-credential-data-not-oracle-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2024-10-15 20:26:18.211541	73	EXECUTED	9:1ae6be29bab7c2aa376f6983b932be37	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	4.29.1	\N	\N	9023974276
8.0.0-updating-credential-data-oracle-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2024-10-15 20:26:18.21448	74	MARK_RAN	9:14706f286953fc9a25286dbd8fb30d97	update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL; update tableName=FED_USER_CREDENTIAL		\N	4.29.1	\N	\N	9023974276
8.0.0-credential-cleanup-fixed	keycloak	META-INF/jpa-changelog-8.0.0.xml	2024-10-15 20:26:18.234449	75	EXECUTED	9:2b9cc12779be32c5b40e2e67711a218b	dropDefaultValue columnName=COUNTER, tableName=CREDENTIAL; dropDefaultValue columnName=DIGITS, tableName=CREDENTIAL; dropDefaultValue columnName=PERIOD, tableName=CREDENTIAL; dropDefaultValue columnName=ALGORITHM, tableName=CREDENTIAL; dropColumn ...		\N	4.29.1	\N	\N	9023974276
8.0.0-resource-tag-support	keycloak	META-INF/jpa-changelog-8.0.0.xml	2024-10-15 20:26:18.266345	76	EXECUTED	9:91fa186ce7a5af127a2d7a91ee083cc5	addColumn tableName=MIGRATION_MODEL; createIndex indexName=IDX_UPDATE_TIME, tableName=MIGRATION_MODEL		\N	4.29.1	\N	\N	9023974276
9.0.0-always-display-client	keycloak	META-INF/jpa-changelog-9.0.0.xml	2024-10-15 20:26:18.27237	77	EXECUTED	9:6335e5c94e83a2639ccd68dd24e2e5ad	addColumn tableName=CLIENT		\N	4.29.1	\N	\N	9023974276
9.0.0-drop-constraints-for-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2024-10-15 20:26:18.275008	78	MARK_RAN	9:6bdb5658951e028bfe16fa0a8228b530	dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5PMT, tableName=RESOURCE_SERVER_PERM_TICKET; dropUniqueConstraint constraintName=UK_FRSR6T700S9V50BU18WS5HA6, tableName=RESOURCE_SERVER_RESOURCE; dropPrimaryKey constraintName=CONSTRAINT_O...		\N	4.29.1	\N	\N	9023974276
9.0.0-increase-column-size-federated-fk	keycloak	META-INF/jpa-changelog-9.0.0.xml	2024-10-15 20:26:18.300334	79	EXECUTED	9:d5bc15a64117ccad481ce8792d4c608f	modifyDataType columnName=CLIENT_ID, tableName=FED_USER_CONSENT; modifyDataType columnName=CLIENT_REALM_CONSTRAINT, tableName=KEYCLOAK_ROLE; modifyDataType columnName=OWNER, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=CLIENT_ID, ta...		\N	4.29.1	\N	\N	9023974276
9.0.0-recreate-constraints-after-column-increase	keycloak	META-INF/jpa-changelog-9.0.0.xml	2024-10-15 20:26:18.303375	80	MARK_RAN	9:077cba51999515f4d3e7ad5619ab592c	addNotNullConstraint columnName=CLIENT_ID, tableName=OFFLINE_CLIENT_SESSION; addNotNullConstraint columnName=OWNER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNullConstraint columnName=REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; addNotNull...		\N	4.29.1	\N	\N	9023974276
9.0.1-add-index-to-client.client_id	keycloak	META-INF/jpa-changelog-9.0.1.xml	2024-10-15 20:26:18.331312	81	EXECUTED	9:be969f08a163bf47c6b9e9ead8ac2afb	createIndex indexName=IDX_CLIENT_ID, tableName=CLIENT		\N	4.29.1	\N	\N	9023974276
9.0.1-KEYCLOAK-12579-drop-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2024-10-15 20:26:18.334044	82	MARK_RAN	9:6d3bb4408ba5a72f39bd8a0b301ec6e3	dropUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.29.1	\N	\N	9023974276
9.0.1-KEYCLOAK-12579-add-not-null-constraint	keycloak	META-INF/jpa-changelog-9.0.1.xml	2024-10-15 20:26:18.340572	83	EXECUTED	9:966bda61e46bebf3cc39518fbed52fa7	addNotNullConstraint columnName=PARENT_GROUP, tableName=KEYCLOAK_GROUP		\N	4.29.1	\N	\N	9023974276
9.0.1-KEYCLOAK-12579-recreate-constraints	keycloak	META-INF/jpa-changelog-9.0.1.xml	2024-10-15 20:26:18.343305	84	MARK_RAN	9:8dcac7bdf7378e7d823cdfddebf72fda	addUniqueConstraint constraintName=SIBLING_NAMES, tableName=KEYCLOAK_GROUP		\N	4.29.1	\N	\N	9023974276
9.0.1-add-index-to-events	keycloak	META-INF/jpa-changelog-9.0.1.xml	2024-10-15 20:26:18.37008	85	EXECUTED	9:7d93d602352a30c0c317e6a609b56599	createIndex indexName=IDX_EVENT_TIME, tableName=EVENT_ENTITY		\N	4.29.1	\N	\N	9023974276
map-remove-ri	keycloak	META-INF/jpa-changelog-11.0.0.xml	2024-10-15 20:26:18.377803	86	EXECUTED	9:71c5969e6cdd8d7b6f47cebc86d37627	dropForeignKeyConstraint baseTableName=REALM, constraintName=FK_TRAF444KK6QRKMS7N56AIWQ5Y; dropForeignKeyConstraint baseTableName=KEYCLOAK_ROLE, constraintName=FK_KJHO5LE2C0RAL09FL8CM9WFW9		\N	4.29.1	\N	\N	9023974276
map-remove-ri	keycloak	META-INF/jpa-changelog-12.0.0.xml	2024-10-15 20:26:18.389405	87	EXECUTED	9:a9ba7d47f065f041b7da856a81762021	dropForeignKeyConstraint baseTableName=REALM_DEFAULT_GROUPS, constraintName=FK_DEF_GROUPS_GROUP; dropForeignKeyConstraint baseTableName=REALM_DEFAULT_ROLES, constraintName=FK_H4WPD7W4HSOOLNI3H0SW7BTJE; dropForeignKeyConstraint baseTableName=CLIENT...		\N	4.29.1	\N	\N	9023974276
12.1.0-add-realm-localization-table	keycloak	META-INF/jpa-changelog-12.0.0.xml	2024-10-15 20:26:18.40483	88	EXECUTED	9:fffabce2bc01e1a8f5110d5278500065	createTable tableName=REALM_LOCALIZATIONS; addPrimaryKey tableName=REALM_LOCALIZATIONS		\N	4.29.1	\N	\N	9023974276
default-roles	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.412309	89	EXECUTED	9:fa8a5b5445e3857f4b010bafb5009957	addColumn tableName=REALM; customChange		\N	4.29.1	\N	\N	9023974276
default-roles-cleanup	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.422571	90	EXECUTED	9:67ac3241df9a8582d591c5ed87125f39	dropTable tableName=REALM_DEFAULT_ROLES; dropTable tableName=CLIENT_DEFAULT_ROLES		\N	4.29.1	\N	\N	9023974276
13.0.0-KEYCLOAK-16844	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.448915	91	EXECUTED	9:ad1194d66c937e3ffc82386c050ba089	createIndex indexName=IDX_OFFLINE_USS_PRELOAD, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
map-remove-ri-13.0.0	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.461059	92	EXECUTED	9:d9be619d94af5a2f5d07b9f003543b91	dropForeignKeyConstraint baseTableName=DEFAULT_CLIENT_SCOPE, constraintName=FK_R_DEF_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SCOPE_CLIENT, constraintName=FK_C_CLI_SCOPE_SCOPE; dropForeignKeyConstraint baseTableName=CLIENT_SC...		\N	4.29.1	\N	\N	9023974276
13.0.0-KEYCLOAK-17992-drop-constraints	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.463872	93	MARK_RAN	9:544d201116a0fcc5a5da0925fbbc3bde	dropPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CLSCOPE_CL, tableName=CLIENT_SCOPE_CLIENT; dropIndex indexName=IDX_CL_CLSCOPE, tableName=CLIENT_SCOPE_CLIENT		\N	4.29.1	\N	\N	9023974276
13.0.0-increase-column-size-federated	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.478055	94	EXECUTED	9:43c0c1055b6761b4b3e89de76d612ccf	modifyDataType columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; modifyDataType columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT		\N	4.29.1	\N	\N	9023974276
13.0.0-KEYCLOAK-17992-recreate-constraints	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.480929	95	MARK_RAN	9:8bd711fd0330f4fe980494ca43ab1139	addNotNullConstraint columnName=CLIENT_ID, tableName=CLIENT_SCOPE_CLIENT; addNotNullConstraint columnName=SCOPE_ID, tableName=CLIENT_SCOPE_CLIENT; addPrimaryKey constraintName=C_CLI_SCOPE_BIND, tableName=CLIENT_SCOPE_CLIENT; createIndex indexName=...		\N	4.29.1	\N	\N	9023974276
json-string-accomodation-fixed	keycloak	META-INF/jpa-changelog-13.0.0.xml	2024-10-15 20:26:18.487959	96	EXECUTED	9:e07d2bc0970c348bb06fb63b1f82ddbf	addColumn tableName=REALM_ATTRIBUTE; update tableName=REALM_ATTRIBUTE; dropColumn columnName=VALUE, tableName=REALM_ATTRIBUTE; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=REALM_ATTRIBUTE		\N	4.29.1	\N	\N	9023974276
14.0.0-KEYCLOAK-11019	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.554976	97	EXECUTED	9:24fb8611e97f29989bea412aa38d12b7	createIndex indexName=IDX_OFFLINE_CSS_PRELOAD, tableName=OFFLINE_CLIENT_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USER, tableName=OFFLINE_USER_SESSION; createIndex indexName=IDX_OFFLINE_USS_BY_USERSESS, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
14.0.0-KEYCLOAK-18286	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.557805	98	MARK_RAN	9:259f89014ce2506ee84740cbf7163aa7	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
14.0.0-KEYCLOAK-18286-revert	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.566696	99	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
14.0.0-KEYCLOAK-18286-supported-dbs	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.595207	100	EXECUTED	9:60ca84a0f8c94ec8c3504a5a3bc88ee8	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
14.0.0-KEYCLOAK-18286-unsupported-dbs	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.598107	101	MARK_RAN	9:d3d977031d431db16e2c181ce49d73e9	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
KEYCLOAK-17267-add-index-to-user-attributes	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.62761	102	EXECUTED	9:0b305d8d1277f3a89a0a53a659ad274c	createIndex indexName=IDX_USER_ATTRIBUTE_NAME, tableName=USER_ATTRIBUTE		\N	4.29.1	\N	\N	9023974276
KEYCLOAK-18146-add-saml-art-binding-identifier	keycloak	META-INF/jpa-changelog-14.0.0.xml	2024-10-15 20:26:18.632498	103	EXECUTED	9:2c374ad2cdfe20e2905a84c8fac48460	customChange		\N	4.29.1	\N	\N	9023974276
15.0.0-KEYCLOAK-18467	keycloak	META-INF/jpa-changelog-15.0.0.xml	2024-10-15 20:26:18.640544	104	EXECUTED	9:47a760639ac597360a8219f5b768b4de	addColumn tableName=REALM_LOCALIZATIONS; update tableName=REALM_LOCALIZATIONS; dropColumn columnName=TEXTS, tableName=REALM_LOCALIZATIONS; renameColumn newColumnName=TEXTS, oldColumnName=TEXTS_NEW, tableName=REALM_LOCALIZATIONS; addNotNullConstrai...		\N	4.29.1	\N	\N	9023974276
17.0.0-9562	keycloak	META-INF/jpa-changelog-17.0.0.xml	2024-10-15 20:26:18.674522	105	EXECUTED	9:a6272f0576727dd8cad2522335f5d99e	createIndex indexName=IDX_USER_SERVICE_ACCOUNT, tableName=USER_ENTITY		\N	4.29.1	\N	\N	9023974276
18.0.0-10625-IDX_ADMIN_EVENT_TIME	keycloak	META-INF/jpa-changelog-18.0.0.xml	2024-10-15 20:26:18.711273	106	EXECUTED	9:015479dbd691d9cc8669282f4828c41d	createIndex indexName=IDX_ADMIN_EVENT_TIME, tableName=ADMIN_EVENT_ENTITY		\N	4.29.1	\N	\N	9023974276
18.0.15-30992-index-consent	keycloak	META-INF/jpa-changelog-18.0.15.xml	2024-10-15 20:26:18.746264	107	EXECUTED	9:80071ede7a05604b1f4906f3bf3b00f0	createIndex indexName=IDX_USCONSENT_SCOPE_ID, tableName=USER_CONSENT_CLIENT_SCOPE		\N	4.29.1	\N	\N	9023974276
19.0.0-10135	keycloak	META-INF/jpa-changelog-19.0.0.xml	2024-10-15 20:26:18.751302	108	EXECUTED	9:9518e495fdd22f78ad6425cc30630221	customChange		\N	4.29.1	\N	\N	9023974276
20.0.0-12964-supported-dbs	keycloak	META-INF/jpa-changelog-20.0.0.xml	2024-10-15 20:26:18.780065	109	EXECUTED	9:e5f243877199fd96bcc842f27a1656ac	createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE		\N	4.29.1	\N	\N	9023974276
20.0.0-12964-unsupported-dbs	keycloak	META-INF/jpa-changelog-20.0.0.xml	2024-10-15 20:26:18.782895	110	MARK_RAN	9:1a6fcaa85e20bdeae0a9ce49b41946a5	createIndex indexName=IDX_GROUP_ATT_BY_NAME_VALUE, tableName=GROUP_ATTRIBUTE		\N	4.29.1	\N	\N	9023974276
client-attributes-string-accomodation-fixed	keycloak	META-INF/jpa-changelog-20.0.0.xml	2024-10-15 20:26:18.79019	111	EXECUTED	9:3f332e13e90739ed0c35b0b25b7822ca	addColumn tableName=CLIENT_ATTRIBUTES; update tableName=CLIENT_ATTRIBUTES; dropColumn columnName=VALUE, tableName=CLIENT_ATTRIBUTES; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
21.0.2-17277	keycloak	META-INF/jpa-changelog-21.0.2.xml	2024-10-15 20:26:18.7942	112	EXECUTED	9:7ee1f7a3fb8f5588f171fb9a6ab623c0	customChange		\N	4.29.1	\N	\N	9023974276
21.1.0-19404	keycloak	META-INF/jpa-changelog-21.1.0.xml	2024-10-15 20:26:18.844673	113	EXECUTED	9:3d7e830b52f33676b9d64f7f2b2ea634	modifyDataType columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=LOGIC, tableName=RESOURCE_SERVER_POLICY; modifyDataType columnName=POLICY_ENFORCE_MODE, tableName=RESOURCE_SERVER		\N	4.29.1	\N	\N	9023974276
21.1.0-19404-2	keycloak	META-INF/jpa-changelog-21.1.0.xml	2024-10-15 20:26:18.848001	114	MARK_RAN	9:627d032e3ef2c06c0e1f73d2ae25c26c	addColumn tableName=RESOURCE_SERVER_POLICY; update tableName=RESOURCE_SERVER_POLICY; dropColumn columnName=DECISION_STRATEGY, tableName=RESOURCE_SERVER_POLICY; renameColumn newColumnName=DECISION_STRATEGY, oldColumnName=DECISION_STRATEGY_NEW, tabl...		\N	4.29.1	\N	\N	9023974276
22.0.0-17484-updated	keycloak	META-INF/jpa-changelog-22.0.0.xml	2024-10-15 20:26:18.852389	115	EXECUTED	9:90af0bfd30cafc17b9f4d6eccd92b8b3	customChange		\N	4.29.1	\N	\N	9023974276
22.0.5-24031	keycloak	META-INF/jpa-changelog-22.0.0.xml	2024-10-15 20:26:18.855018	116	MARK_RAN	9:a60d2d7b315ec2d3eba9e2f145f9df28	customChange		\N	4.29.1	\N	\N	9023974276
23.0.0-12062	keycloak	META-INF/jpa-changelog-23.0.0.xml	2024-10-15 20:26:18.861512	117	EXECUTED	9:2168fbe728fec46ae9baf15bf80927b8	addColumn tableName=COMPONENT_CONFIG; update tableName=COMPONENT_CONFIG; dropColumn columnName=VALUE, tableName=COMPONENT_CONFIG; renameColumn newColumnName=VALUE, oldColumnName=VALUE_NEW, tableName=COMPONENT_CONFIG		\N	4.29.1	\N	\N	9023974276
23.0.0-17258	keycloak	META-INF/jpa-changelog-23.0.0.xml	2024-10-15 20:26:18.866937	118	EXECUTED	9:36506d679a83bbfda85a27ea1864dca8	addColumn tableName=EVENT_ENTITY		\N	4.29.1	\N	\N	9023974276
24.0.0-9758	keycloak	META-INF/jpa-changelog-24.0.0.xml	2024-10-15 20:26:18.958385	119	EXECUTED	9:502c557a5189f600f0f445a9b49ebbce	addColumn tableName=USER_ATTRIBUTE; addColumn tableName=FED_USER_ATTRIBUTE; createIndex indexName=USER_ATTR_LONG_VALUES, tableName=USER_ATTRIBUTE; createIndex indexName=FED_USER_ATTR_LONG_VALUES, tableName=FED_USER_ATTRIBUTE; createIndex indexName...		\N	4.29.1	\N	\N	9023974276
24.0.0-9758-2	keycloak	META-INF/jpa-changelog-24.0.0.xml	2024-10-15 20:26:18.962456	120	EXECUTED	9:bf0fdee10afdf597a987adbf291db7b2	customChange		\N	4.29.1	\N	\N	9023974276
24.0.0-26618-drop-index-if-present	keycloak	META-INF/jpa-changelog-24.0.0.xml	2024-10-15 20:26:18.966939	121	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
24.0.0-26618-reindex	keycloak	META-INF/jpa-changelog-24.0.0.xml	2024-10-15 20:26:18.992271	122	EXECUTED	9:08707c0f0db1cef6b352db03a60edc7f	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
24.0.2-27228	keycloak	META-INF/jpa-changelog-24.0.2.xml	2024-10-15 20:26:18.996214	123	EXECUTED	9:eaee11f6b8aa25d2cc6a84fb86fc6238	customChange		\N	4.29.1	\N	\N	9023974276
24.0.2-27967-drop-index-if-present	keycloak	META-INF/jpa-changelog-24.0.2.xml	2024-10-15 20:26:18.998726	124	MARK_RAN	9:04baaf56c116ed19951cbc2cca584022	dropIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
24.0.2-27967-reindex	keycloak	META-INF/jpa-changelog-24.0.2.xml	2024-10-15 20:26:19.001551	125	MARK_RAN	9:d3d977031d431db16e2c181ce49d73e9	createIndex indexName=IDX_CLIENT_ATT_BY_NAME_VALUE, tableName=CLIENT_ATTRIBUTES		\N	4.29.1	\N	\N	9023974276
25.0.0-28265-tables	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.009433	126	EXECUTED	9:deda2df035df23388af95bbd36c17cef	addColumn tableName=OFFLINE_USER_SESSION; addColumn tableName=OFFLINE_CLIENT_SESSION		\N	4.29.1	\N	\N	9023974276
25.0.0-28265-index-creation	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.036646	127	EXECUTED	9:3e96709818458ae49f3c679ae58d263a	createIndex indexName=IDX_OFFLINE_USS_BY_LAST_SESSION_REFRESH, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
25.0.0-28265-index-cleanup	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.04389	128	EXECUTED	9:8c0cfa341a0474385b324f5c4b2dfcc1	dropIndex indexName=IDX_OFFLINE_USS_CREATEDON, tableName=OFFLINE_USER_SESSION; dropIndex indexName=IDX_OFFLINE_USS_PRELOAD, tableName=OFFLINE_USER_SESSION; dropIndex indexName=IDX_OFFLINE_USS_BY_USERSESS, tableName=OFFLINE_USER_SESSION; dropIndex ...		\N	4.29.1	\N	\N	9023974276
25.0.0-28265-index-2-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.046563	129	MARK_RAN	9:b7ef76036d3126bb83c2423bf4d449d6	createIndex indexName=IDX_OFFLINE_USS_BY_BROKER_SESSION_ID, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
25.0.0-28265-index-2-not-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.072304	130	EXECUTED	9:23396cf51ab8bc1ae6f0cac7f9f6fcf7	createIndex indexName=IDX_OFFLINE_USS_BY_BROKER_SESSION_ID, tableName=OFFLINE_USER_SESSION		\N	4.29.1	\N	\N	9023974276
25.0.0-org	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.107786	131	EXECUTED	9:5c859965c2c9b9c72136c360649af157	createTable tableName=ORG; addUniqueConstraint constraintName=UK_ORG_NAME, tableName=ORG; addUniqueConstraint constraintName=UK_ORG_GROUP, tableName=ORG; createTable tableName=ORG_DOMAIN		\N	4.29.1	\N	\N	9023974276
unique-consentuser	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.125074	132	EXECUTED	9:5857626a2ea8767e9a6c66bf3a2cb32f	customChange; dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_LOCAL_CONSENT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_EXTERNAL_CONSENT, tableName=...		\N	4.29.1	\N	\N	9023974276
unique-consentuser-mysql	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.128009	133	MARK_RAN	9:b79478aad5adaa1bc428e31563f55e8e	customChange; dropUniqueConstraint constraintName=UK_JKUWUVD56ONTGSUHOGM8UEWRT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_LOCAL_CONSENT, tableName=USER_CONSENT; addUniqueConstraint constraintName=UK_EXTERNAL_CONSENT, tableName=...		\N	4.29.1	\N	\N	9023974276
25.0.0-28861-index-creation	keycloak	META-INF/jpa-changelog-25.0.0.xml	2024-10-15 20:26:19.175049	134	EXECUTED	9:b9acb58ac958d9ada0fe12a5d4794ab1	createIndex indexName=IDX_PERM_TICKET_REQUESTER, tableName=RESOURCE_SERVER_PERM_TICKET; createIndex indexName=IDX_PERM_TICKET_OWNER, tableName=RESOURCE_SERVER_PERM_TICKET		\N	4.29.1	\N	\N	9023974276
26.0.0-org-alias	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.186132	135	EXECUTED	9:6ef7d63e4412b3c2d66ed179159886a4	addColumn tableName=ORG; update tableName=ORG; addNotNullConstraint columnName=ALIAS, tableName=ORG; addUniqueConstraint constraintName=UK_ORG_ALIAS, tableName=ORG		\N	4.29.1	\N	\N	9023974276
26.0.0-org-group	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.196809	136	EXECUTED	9:da8e8087d80ef2ace4f89d8c5b9ca223	addColumn tableName=KEYCLOAK_GROUP; update tableName=KEYCLOAK_GROUP; addNotNullConstraint columnName=TYPE, tableName=KEYCLOAK_GROUP; customChange		\N	4.29.1	\N	\N	9023974276
26.0.0-org-indexes	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.22463	137	EXECUTED	9:79b05dcd610a8c7f25ec05135eec0857	createIndex indexName=IDX_ORG_DOMAIN_ORG_ID, tableName=ORG_DOMAIN		\N	4.29.1	\N	\N	9023974276
26.0.0-org-group-membership	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.231325	138	EXECUTED	9:a6ace2ce583a421d89b01ba2a28dc2d4	addColumn tableName=USER_GROUP_MEMBERSHIP; update tableName=USER_GROUP_MEMBERSHIP; addNotNullConstraint columnName=MEMBERSHIP_TYPE, tableName=USER_GROUP_MEMBERSHIP		\N	4.29.1	\N	\N	9023974276
31296-persist-revoked-access-tokens	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.241954	139	EXECUTED	9:64ef94489d42a358e8304b0e245f0ed4	createTable tableName=REVOKED_TOKEN; addPrimaryKey constraintName=CONSTRAINT_RT, tableName=REVOKED_TOKEN		\N	4.29.1	\N	\N	9023974276
31725-index-persist-revoked-access-tokens	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.278249	140	EXECUTED	9:b994246ec2bf7c94da881e1d28782c7b	createIndex indexName=IDX_REV_TOKEN_ON_EXPIRE, tableName=REVOKED_TOKEN		\N	4.29.1	\N	\N	9023974276
26.0.0-idps-for-login	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.326806	141	EXECUTED	9:51f5fffadf986983d4bd59582c6c1604	addColumn tableName=IDENTITY_PROVIDER; createIndex indexName=IDX_IDP_REALM_ORG, tableName=IDENTITY_PROVIDER; createIndex indexName=IDX_IDP_FOR_LOGIN, tableName=IDENTITY_PROVIDER; customChange		\N	4.29.1	\N	\N	9023974276
26.0.0-32583-drop-redundant-index-on-client-session	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.33251	142	EXECUTED	9:24972d83bf27317a055d234187bb4af9	dropIndex indexName=IDX_US_SESS_ID_ON_CL_SESS, tableName=OFFLINE_CLIENT_SESSION		\N	4.29.1	\N	\N	9023974276
26.0.0.32582-remove-tables-user-session-user-session-note-and-client-session	keycloak	META-INF/jpa-changelog-26.0.0.xml	2024-10-15 20:26:19.35436	143	EXECUTED	9:febdc0f47f2ed241c59e60f58c3ceea5	dropTable tableName=CLIENT_SESSION_ROLE; dropTable tableName=CLIENT_SESSION_NOTE; dropTable tableName=CLIENT_SESSION_PROT_MAPPER; dropTable tableName=CLIENT_SESSION_AUTH_STATUS; dropTable tableName=CLIENT_USER_SESSION_NOTE; dropTable tableName=CLI...		\N	4.29.1	\N	\N	9023974276
\.


--
-- Data for Name: databasechangeloglock; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.databasechangeloglock (id, locked, lockgranted, lockedby) FROM stdin;
1	f	\N	\N
1000	f	\N	\N
\.


--
-- Data for Name: default_client_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.default_client_scope (realm_id, scope_id, default_scope) FROM stdin;
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	15324f7e-f5bc-4e29-900e-464a36a51ac8	f
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	d00a9373-d558-43ef-b0b3-d197537acf26	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	756440de-7d62-4f2b-aa1e-21612b4d747b	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	9189c2f5-780a-4347-89aa-bb708ea0b969	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	9d0e598a-91b2-4e09-a240-de8f8b0bb287	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c2b49809-d53a-449d-8918-828b07ed42d5	f
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	cf19844b-ca5d-4e1f-942a-0c24bb75018b	f
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	aa2067c1-393a-476e-914a-cbeef275af20	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	7ceeed05-cc86-4863-986c-f99a80c79c23	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77	f
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	426c7d8c-da42-4f46-8f7c-3dca6582a547	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e8d6020e-1b3d-4b1d-a390-4697c8b54ade	t
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	af569dea-9156-434a-903b-cda6ab43876a	f
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	be2edb6c-df16-4e4e-b393-fc338fdc6ad4	f
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	db5dbc08-6e34-41a1-8dcc-04bbc89e55f9	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	2318ad8c-852e-4888-8aaf-b43e86ab596b	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	de37461f-0e67-4f6e-86c8-df54cab2d27a	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	af60348c-4eb0-40a0-a6c2-d7884782dc55	f
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	cd449209-e0f7-4a55-877c-f7bb7e96e233	f
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	1e9464fe-767e-42bf-a6b7-d023f9db9fdb	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	5dd2a98c-7928-4e6f-a3f1-7840459a74b1	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	4c688c12-0165-4ec5-9745-67cf86f04be4	f
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e2faba26-586b-4646-b495-db2ca9ae59e3	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	726bbb5a-7140-46b4-9812-e5bcf6065075	t
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	a2ce9b1d-8529-4870-b8d5-52d47d668a24	f
\.


--
-- Data for Name: event_entity; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.event_entity (id, client_id, details_json, error, ip_address, realm_id, session_id, event_time, type, user_id, details_json_long_value) FROM stdin;
\.


--
-- Data for Name: fed_user_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_attribute (id, name, user_id, realm_id, storage_provider_id, value, long_value_hash, long_value_hash_lower_case, long_value) FROM stdin;
\.


--
-- Data for Name: fed_user_consent; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_consent (id, client_id, user_id, realm_id, storage_provider_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: fed_user_consent_cl_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_consent_cl_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: fed_user_credential; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_credential (id, salt, type, created_date, user_id, realm_id, storage_provider_id, user_label, secret_data, credential_data, priority) FROM stdin;
\.


--
-- Data for Name: fed_user_group_membership; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_group_membership (group_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_required_action; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_required_action (required_action, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: fed_user_role_mapping; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.fed_user_role_mapping (role_id, user_id, realm_id, storage_provider_id) FROM stdin;
\.


--
-- Data for Name: federated_identity; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.federated_identity (identity_provider, realm_id, federated_user_id, federated_username, token, user_id) FROM stdin;
\.


--
-- Data for Name: federated_user; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.federated_user (id, storage_provider_id, realm_id) FROM stdin;
\.


--
-- Data for Name: group_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.group_attribute (id, name, value, group_id) FROM stdin;
\.


--
-- Data for Name: group_role_mapping; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.group_role_mapping (role_id, group_id) FROM stdin;
\.


--
-- Data for Name: identity_provider; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.identity_provider (internal_id, enabled, provider_alias, provider_id, store_token, authenticate_by_default, realm_id, add_token_role, trust_email, first_broker_login_flow_id, post_broker_login_flow_id, provider_display_name, link_only, organization_id, hide_on_login) FROM stdin;
\.


--
-- Data for Name: identity_provider_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.identity_provider_config (identity_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: identity_provider_mapper; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.identity_provider_mapper (id, name, idp_alias, idp_mapper_name, realm_id) FROM stdin;
\.


--
-- Data for Name: idp_mapper_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.idp_mapper_config (idp_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: keycloak_group; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.keycloak_group (id, name, parent_group, realm_id, type) FROM stdin;
\.


--
-- Data for Name: keycloak_role; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.keycloak_role (id, client_realm_constraint, client_role, description, name, realm_id, client, realm) FROM stdin;
1300e97a-2599-431d-8169-937df66ace29	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	${role_default-roles}	default-roles-master	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	\N
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	${role_admin}	admin	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	\N
73a8cfb4-2f8d-4e71-a383-c59f23015994	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	${role_create-realm}	create-realm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	\N
4909c761-7ef5-45a8-a0be-9bac3def2c41	da4c211e-5148-4471-8884-d95420b88548	t	${role_create-client}	create-client	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
013bd164-f10b-427b-8e9a-a78859c73961	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-realm}	view-realm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
0b2db8fe-8417-4628-8767-becbb6ed2ce1	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-users}	view-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
084baff1-aee8-45a3-9f78-d0458f13537c	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-clients}	view-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
bcb932fb-8121-4a18-8c4c-0104d624abef	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-events}	view-events	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
52cee13d-2af2-4349-b998-e2b164f904cf	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-identity-providers}	view-identity-providers	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
00d339a9-9eae-4325-84d4-77720a3cd90d	da4c211e-5148-4471-8884-d95420b88548	t	${role_view-authorization}	view-authorization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
dcc09017-7a5d-45b5-920a-f3b7c8d39e50	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-realm}	manage-realm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
d06e4a89-5287-4b66-a263-83e185aea651	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-users}	manage-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
13ca6cd6-31d6-4292-99e2-a79d640c7fd2	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-clients}	manage-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
6de04d44-1c75-4f4d-a501-beae243ecc9c	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-events}	manage-events	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
07c25ed1-c2ac-41f7-9226-6a167848f8b3	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-identity-providers}	manage-identity-providers	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
b695512d-9f72-4234-9a93-4331f4cea609	da4c211e-5148-4471-8884-d95420b88548	t	${role_manage-authorization}	manage-authorization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
38b81844-dd2e-4027-92da-e90e2b97f7a9	da4c211e-5148-4471-8884-d95420b88548	t	${role_query-users}	query-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
e22a7524-f314-45bc-bf27-dabf0a6e98b0	da4c211e-5148-4471-8884-d95420b88548	t	${role_query-clients}	query-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
b05d9795-f2f4-4959-971c-c75619037108	da4c211e-5148-4471-8884-d95420b88548	t	${role_query-realms}	query-realms	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
59eab1ac-e8f9-4a1f-8a9d-a677db0f01db	da4c211e-5148-4471-8884-d95420b88548	t	${role_query-groups}	query-groups	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
a0e86062-51e5-47b2-bafd-c1305fdf7b1a	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_view-profile}	view-profile	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
c3612af0-a78d-4863-bc60-cfee5b0471c1	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_manage-account}	manage-account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
7adff7f4-d0eb-47b2-b7b4-a7c4d437bf81	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_manage-account-links}	manage-account-links	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
37523bef-9a4c-482b-9b54-83f6effe49d0	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_view-applications}	view-applications	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
5d97954d-865f-4f37-97b4-87f62a604dc7	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_view-consent}	view-consent	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
4603ece7-68b0-4063-b18e-487dc31f79c7	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_manage-consent}	manage-consent	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
8d03dc4f-0cbf-442a-8e16-11d55235baf8	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_view-groups}	view-groups	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
9f15485f-8468-4bc7-9445-7b78cfbe606f	6125bc74-bea8-40b9-b320-d88778d34fba	t	${role_delete-account}	delete-account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	6125bc74-bea8-40b9-b320-d88778d34fba	\N
eff2cf69-b056-47ae-b828-01e70a0c2d0d	80a65571-abe9-4b9f-8140-be9172234c3c	t	${role_read-token}	read-token	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	80a65571-abe9-4b9f-8140-be9172234c3c	\N
5154abe9-e90f-44ca-ba88-e1c0df330570	da4c211e-5148-4471-8884-d95420b88548	t	${role_impersonation}	impersonation	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	da4c211e-5148-4471-8884-d95420b88548	\N
67e69687-c5af-422f-9c6d-dd9ca6064817	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	${role_offline-access}	offline_access	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	\N
251e2a5f-279a-4f24-a4a9-84ecb1afc201	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	${role_uma_authorization}	uma_authorization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	\N	\N
3c4a339d-6f51-4bd0-89ae-6df6717752b1	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	${role_default-roles}	default-roles-test	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N	\N
5afa69c0-39b4-437e-9fd9-62bc2bd3a8ac	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_create-client}	create-client	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
0a8e0d55-bc6b-4a24-8d1a-d7b9ce8cfeca	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-realm}	view-realm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
697727aa-0941-4221-a764-8455d785113a	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-users}	view-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
efde6b3d-bd27-40c7-bb7a-77f1e53ae027	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-clients}	view-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
be558d96-d932-49e2-bdf0-bed1cb62f195	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-events}	view-events	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
89c75bb6-e100-4aa2-a01b-24ff61532325	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-identity-providers}	view-identity-providers	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
40298bbb-de9e-4773-9556-672e334fb790	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_view-authorization}	view-authorization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
48658c00-7874-4629-a47e-f2a810e5c73d	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-realm}	manage-realm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
006beb79-4f32-4d27-a1c7-6e7208bda9fa	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-users}	manage-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
0c129943-2559-4c17-bd40-d4c2fd0b849e	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-clients}	manage-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
5f1473be-13e6-4c35-9877-ccb645cabe2c	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-events}	manage-events	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
aaaaed08-fd2f-44dd-834d-87ed8362eb6c	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-identity-providers}	manage-identity-providers	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
f85a8f5c-dfe8-4c61-b2d0-23a8d0cf9642	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_manage-authorization}	manage-authorization	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
7281a701-8a2e-4e5e-8097-f2196824dfbd	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_query-users}	query-users	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
88e1a2d8-d44d-4324-a266-21ae8bae06ea	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_query-clients}	query-clients	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
1bb4ab62-5767-460b-bdfb-544ff862ac2c	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_query-realms}	query-realms	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
1a15ebf6-77d9-4111-bd0b-6db91bbb793b	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_query-groups}	query-groups	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
13628d05-9caf-480c-ae1c-92ea26de42b1	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_realm-admin}	realm-admin	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
12f21043-1b94-4d7c-a025-00dbd116a903	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_create-client}	create-client	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
60e4c13b-fba2-4c49-a17f-d606f0595e9a	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-realm}	view-realm	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
f26c857f-0a8f-4112-8b0c-cefa11978f2b	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-users}	view-users	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
4025a7c7-b45c-4478-8da1-6e046124a4ef	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-clients}	view-clients	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
daf5d3a9-cef3-41d8-b4e3-e6ebe5d7bfa1	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-events}	view-events	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
3bb70329-f2bd-4800-bd67-654ab12a9bc6	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-identity-providers}	view-identity-providers	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
316c8c11-5140-45dc-9790-6f262c7a92f2	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_view-authorization}	view-authorization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
8382deaa-a5f7-42e4-815b-460b09931bbf	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-realm}	manage-realm	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
792be8d1-a9a3-4746-8985-ca265f0a1d90	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-users}	manage-users	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
994af3d5-88c3-4abc-9d25-67e0ac50fe06	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-clients}	manage-clients	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
a3110636-4295-4e5d-aacd-09625d2e446a	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-events}	manage-events	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
8d47f7ec-68c8-4ee1-8d2c-9bd9c120eeba	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-identity-providers}	manage-identity-providers	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
2e73f013-7426-4021-baaf-2023c2bd4b52	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_manage-authorization}	manage-authorization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
2ad3a054-c1a8-4b78-8a82-6a9469cae5d3	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_query-users}	query-users	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
7fb645d9-8a53-456f-8ea9-a2cabc80dac3	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_query-clients}	query-clients	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
6274cab9-6eab-42fa-aabd-bac08d5309f4	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_query-realms}	query-realms	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
3641a812-b9e4-4822-95d4-eea7d8810ba0	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_query-groups}	query-groups	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
a2a94e10-852a-4beb-abd9-c56db1904bba	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_view-profile}	view-profile	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
3371bb12-52d1-4542-a96e-0a9dac54e424	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_manage-account}	manage-account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
4ccbdbd2-b97d-4a37-8173-5dda28f12750	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_manage-account-links}	manage-account-links	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
096d3e08-2423-48f4-8038-57ea467aea9d	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_view-applications}	view-applications	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
7ca13251-2fdc-4a27-9318-c5db26e0a813	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_view-consent}	view-consent	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
8dbf782d-4c54-4083-92f5-0055148ffeb9	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_manage-consent}	manage-consent	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
3872bf40-d0af-4bd6-a810-e312d722fce5	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_view-groups}	view-groups	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
ce68637a-57d6-4bb2-ab5d-5db0ce0d5f0d	6f74340e-b12f-46cb-b362-f59b37cc8930	t	${role_delete-account}	delete-account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	6f74340e-b12f-46cb-b362-f59b37cc8930	\N
53e36238-93ce-41e5-a98e-98bc18d89700	e927bf1e-34ba-4182-9815-66a5c84b7a23	t	${role_impersonation}	impersonation	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	e927bf1e-34ba-4182-9815-66a5c84b7a23	\N
cca7428b-0082-4284-9ce3-fe103d6daaf7	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	t	${role_impersonation}	impersonation	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	34634dbe-90fc-4a4a-8bc6-65c2ee44ecf1	\N
cbe2a382-5d41-456e-8238-0e5c4cd023c8	28fedf47-b677-460d-99e8-b30a2f48ef23	t	${role_read-token}	read-token	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	28fedf47-b677-460d-99e8-b30a2f48ef23	\N
092ee966-a8ce-4aa8-b6af-ab9aef05d48d	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	${role_offline-access}	offline_access	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N	\N
f1be31ec-7c7b-46b1-93b2-d67a7371ca29	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	${role_uma_authorization}	uma_authorization	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	\N	\N
\.


--
-- Data for Name: migration_model; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.migration_model (id, version, update_time) FROM stdin;
egxvv	26.0.0	1729023979
\.


--
-- Data for Name: offline_client_session; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.offline_client_session (user_session_id, client_id, offline_flag, "timestamp", data, client_storage_provider, external_client_id, version) FROM stdin;
eef4d077-d043-400a-b7b8-cee63519862e	1fec1117-a310-4f9d-9373-1c76e8b7d64b	0	1729025262	{"authMethod":"openid-connect","redirectUri":"https://auth.goblin.local/admin/master/console/#/master/users","notes":{"clientId":"1fec1117-a310-4f9d-9373-1c76e8b7d64b","userSessionRememberMe":"true","iss":"https://auth.goblin.local/realms/master","startedAt":"1729025262","response_type":"code","level-of-authentication":"-1","code_challenge_method":"S256","nonce":"85a2b7de-4c02-4e26-a8cc-7191d51763c0","response_mode":"query","scope":"openid","userSessionStartedAt":"1729025262","redirect_uri":"https://auth.goblin.local/admin/master/console/#/master/users","state":"7bd1f19f-0b8b-4de7-92f8-5710aa3dc7a6","code_challenge":"qx9kJSvgVOKtpFkGOwumyRA9LQyOB-xPHfdsWXSwS-M"}}	local	local	0
\.


--
-- Data for Name: offline_user_session; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.offline_user_session (user_session_id, user_id, realm_id, created_on, offline_flag, data, last_session_refresh, broker_session_id, version) FROM stdin;
eef4d077-d043-400a-b7b8-cee63519862e	d5b2a49e-edef-49c1-961f-5d4e562a7659	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	1729025262	0	{"ipAddress":"172.20.0.2","authMethod":"openid-connect","rememberMe":true,"started":0,"notes":{"KC_DEVICE_NOTE":"eyJpcEFkZHJlc3MiOiIxNzIuMjAuMC4yIiwib3MiOiJMaW51eCIsIm9zVmVyc2lvbiI6IlVua25vd24iLCJicm93c2VyIjoiRmlyZWZveC8xMzEuMCIsImRldmljZSI6Ik90aGVyIiwibGFzdEFjY2VzcyI6MCwibW9iaWxlIjpmYWxzZX0=","AUTH_TIME":"1729025262","authenticators-completed":"{\\"d51e0eec-1a9f-4ed7-9c58-13499a7a1741\\":1729025262}"},"state":"LOGGED_IN"}	1729025262	\N	0
\.


--
-- Data for Name: org; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.org (id, enabled, realm_id, group_id, name, description, alias, redirect_url) FROM stdin;
\.


--
-- Data for Name: org_domain; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.org_domain (id, name, verified, org_id) FROM stdin;
\.


--
-- Data for Name: policy_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.policy_config (policy_id, name, value) FROM stdin;
\.


--
-- Data for Name: protocol_mapper; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.protocol_mapper (id, name, protocol, protocol_mapper_name, client_id, client_scope_id) FROM stdin;
8127f488-aa79-446e-b36d-e3e0cab5fc05	audience resolve	openid-connect	oidc-audience-resolve-mapper	66a0b273-0636-4348-8af9-896341a374ed	\N
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	locale	openid-connect	oidc-usermodel-attribute-mapper	1fec1117-a310-4f9d-9373-1c76e8b7d64b	\N
97dcd361-bfe2-4a33-9dc0-096ce00c2648	role list	saml	saml-role-list-mapper	\N	d00a9373-d558-43ef-b0b3-d197537acf26
1561f88d-55ff-441c-8929-ed5280302302	organization	saml	saml-organization-membership-mapper	\N	756440de-7d62-4f2b-aa1e-21612b4d747b
0ee7b915-ff3c-472f-8b20-c973dd404e95	full name	openid-connect	oidc-full-name-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
9b283cde-ce68-4473-b11f-40eeb9954a39	family name	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
46c17475-eb37-44d8-bec3-b28f9c0837e7	given name	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
7b804119-1f0b-4048-b6a6-00e8af01c4de	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
c6fd97cd-e858-4b4b-ac19-22c453c0b470	username	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
d9b607cf-eeef-4ae7-a698-fc23e04bce89	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
66230793-eaeb-4dbb-b96c-5116c574a6a2	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
ed8cba79-1ec0-4260-8135-2710b8d562ab	website	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
ee0254c2-ad63-422d-94fe-e20ef7048221	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
6853ea43-8170-41b2-b5eb-43042da64e40	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
b1170590-3921-433b-bd7a-69a47c4ccf6a	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	9189c2f5-780a-4347-89aa-bb708ea0b969
c78b2e3c-bf20-493c-a095-980d20064d29	email	openid-connect	oidc-usermodel-attribute-mapper	\N	9d0e598a-91b2-4e09-a240-de8f8b0bb287
1b65b2a1-f688-413e-bf54-00c854f4ac0a	email verified	openid-connect	oidc-usermodel-property-mapper	\N	9d0e598a-91b2-4e09-a240-de8f8b0bb287
33247e00-1948-4bde-a5bc-14023dad8e85	address	openid-connect	oidc-address-mapper	\N	c2b49809-d53a-449d-8918-828b07ed42d5
6d5783ed-b4bc-4300-9f81-78aba0962639	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	cf19844b-ca5d-4e1f-942a-0c24bb75018b
346312c3-e426-418d-beea-498212b7b8ce	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	cf19844b-ca5d-4e1f-942a-0c24bb75018b
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	aa2067c1-393a-476e-914a-cbeef275af20
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	aa2067c1-393a-476e-914a-cbeef275af20
2d9dd7ec-6056-4fb7-b732-a297aae69f5e	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	aa2067c1-393a-476e-914a-cbeef275af20
594adb51-bcef-4606-a24f-fa2fbf8ff2bc	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	7ceeed05-cc86-4863-986c-f99a80c79c23
7a3ced81-b07e-45a4-a49e-75d86c3d9030	upn	openid-connect	oidc-usermodel-attribute-mapper	\N	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77
88492a9d-bad2-4074-a743-13018861f9dd	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	c42b6c8f-bff1-4d3a-b23c-e0c90727ed77
2e713d95-f3c6-446b-bdf8-b3ac5228f653	acr loa level	openid-connect	oidc-acr-mapper	\N	426c7d8c-da42-4f46-8f7c-3dca6582a547
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	auth_time	openid-connect	oidc-usersessionmodel-note-mapper	\N	e8d6020e-1b3d-4b1d-a390-4697c8b54ade
51050e6d-9577-4468-915b-fe5e460e1216	sub	openid-connect	oidc-sub-mapper	\N	e8d6020e-1b3d-4b1d-a390-4697c8b54ade
68e24256-c3d8-46aa-845a-d94957ecbd9d	organization	openid-connect	oidc-organization-membership-mapper	\N	af569dea-9156-434a-903b-cda6ab43876a
d5c72234-7954-47c3-b956-f6acf34506cb	audience resolve	openid-connect	oidc-audience-resolve-mapper	d193cc0b-5a5e-44a8-8003-9bcf5828a59f	\N
a658a2b7-691a-44ef-adb3-7450d1ea1c9b	role list	saml	saml-role-list-mapper	\N	db5dbc08-6e34-41a1-8dcc-04bbc89e55f9
83cbd0d4-0ea7-4e85-956b-0b17323eb166	organization	saml	saml-organization-membership-mapper	\N	2318ad8c-852e-4888-8aaf-b43e86ab596b
69d3aa65-8947-469a-9f80-a903e7da3634	full name	openid-connect	oidc-full-name-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	family name	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
e048153d-2120-4d38-b771-bcec06b3f79d	given name	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
b42afc09-40a2-44ae-86fd-26dcbeed9f35	middle name	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
bec6d813-da36-49a5-adcd-2d97a1df7322	nickname	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
b7638da7-ce76-4da0-b1f7-584b63555a53	username	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
92b8a190-a658-46b8-a076-940ab79d9401	profile	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
5b499ee6-dbae-49d6-806c-20a9ff95c190	picture	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
100293dc-c6b0-4e68-8787-8f5e6aae38e0	website	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	gender	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	birthdate	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
e9f78452-61bc-49b9-8639-c57836e71cfc	zoneinfo	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
a4c12cc6-00e6-4383-b079-eeafd82180ed	locale	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	updated at	openid-connect	oidc-usermodel-attribute-mapper	\N	de37461f-0e67-4f6e-86c8-df54cab2d27a
484cd138-5728-4d8c-aae4-e9e103a7ea89	email	openid-connect	oidc-usermodel-attribute-mapper	\N	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a
a323d623-7b09-44ba-ac4e-07864108776f	email verified	openid-connect	oidc-usermodel-property-mapper	\N	2e45182a-e5e8-4e18-ba4b-3c8531b52d7a
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	address	openid-connect	oidc-address-mapper	\N	af60348c-4eb0-40a0-a6c2-d7884782dc55
a51cbe6b-40d9-4428-8e42-6ce249c234d7	phone number	openid-connect	oidc-usermodel-attribute-mapper	\N	cd449209-e0f7-4a55-877c-f7bb7e96e233
e5241524-586b-43e0-8a22-90ec12dae96e	phone number verified	openid-connect	oidc-usermodel-attribute-mapper	\N	cd449209-e0f7-4a55-877c-f7bb7e96e233
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	realm roles	openid-connect	oidc-usermodel-realm-role-mapper	\N	1e9464fe-767e-42bf-a6b7-d023f9db9fdb
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	client roles	openid-connect	oidc-usermodel-client-role-mapper	\N	1e9464fe-767e-42bf-a6b7-d023f9db9fdb
aabe4a00-9dc2-4681-ad02-b588e78a66b5	audience resolve	openid-connect	oidc-audience-resolve-mapper	\N	1e9464fe-767e-42bf-a6b7-d023f9db9fdb
3b4c4a94-8762-4716-af87-be7f8ff5dc67	allowed web origins	openid-connect	oidc-allowed-origins-mapper	\N	5dd2a98c-7928-4e6f-a3f1-7840459a74b1
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	upn	openid-connect	oidc-usermodel-attribute-mapper	\N	4c688c12-0165-4ec5-9745-67cf86f04be4
60085b44-1cdb-47da-8b91-ceaa60729d47	groups	openid-connect	oidc-usermodel-realm-role-mapper	\N	4c688c12-0165-4ec5-9745-67cf86f04be4
a28c5516-b328-482e-a6a3-4497bb96a38c	acr loa level	openid-connect	oidc-acr-mapper	\N	e2faba26-586b-4646-b495-db2ca9ae59e3
e4619dd0-473d-41d2-805f-09c1155fa1c1	auth_time	openid-connect	oidc-usersessionmodel-note-mapper	\N	726bbb5a-7140-46b4-9812-e5bcf6065075
1576b4e8-adc4-4dd5-999f-1cca84179345	sub	openid-connect	oidc-sub-mapper	\N	726bbb5a-7140-46b4-9812-e5bcf6065075
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	organization	openid-connect	oidc-organization-membership-mapper	\N	a2ce9b1d-8529-4870-b8d5-52d47d668a24
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	locale	openid-connect	oidc-usermodel-attribute-mapper	09c0b19b-3328-44b8-b0d5-983e6b4b358e	\N
\.


--
-- Data for Name: protocol_mapper_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.protocol_mapper_config (protocol_mapper_id, value, name) FROM stdin;
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	true	introspection.token.claim
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	true	userinfo.token.claim
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	locale	user.attribute
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	true	id.token.claim
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	true	access.token.claim
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	locale	claim.name
bc280ec5-3a6e-4d03-b85c-d3a56a4c60a7	String	jsonType.label
97dcd361-bfe2-4a33-9dc0-096ce00c2648	false	single
97dcd361-bfe2-4a33-9dc0-096ce00c2648	Basic	attribute.nameformat
97dcd361-bfe2-4a33-9dc0-096ce00c2648	Role	attribute.name
0ee7b915-ff3c-472f-8b20-c973dd404e95	true	introspection.token.claim
0ee7b915-ff3c-472f-8b20-c973dd404e95	true	userinfo.token.claim
0ee7b915-ff3c-472f-8b20-c973dd404e95	true	id.token.claim
0ee7b915-ff3c-472f-8b20-c973dd404e95	true	access.token.claim
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	true	introspection.token.claim
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	true	userinfo.token.claim
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	zoneinfo	user.attribute
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	true	id.token.claim
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	true	access.token.claim
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	zoneinfo	claim.name
1db08e5d-bbcb-40e9-b6f6-8a86c7aa47e6	String	jsonType.label
46c17475-eb37-44d8-bec3-b28f9c0837e7	true	introspection.token.claim
46c17475-eb37-44d8-bec3-b28f9c0837e7	true	userinfo.token.claim
46c17475-eb37-44d8-bec3-b28f9c0837e7	firstName	user.attribute
46c17475-eb37-44d8-bec3-b28f9c0837e7	true	id.token.claim
46c17475-eb37-44d8-bec3-b28f9c0837e7	true	access.token.claim
46c17475-eb37-44d8-bec3-b28f9c0837e7	given_name	claim.name
46c17475-eb37-44d8-bec3-b28f9c0837e7	String	jsonType.label
66230793-eaeb-4dbb-b96c-5116c574a6a2	true	introspection.token.claim
66230793-eaeb-4dbb-b96c-5116c574a6a2	true	userinfo.token.claim
66230793-eaeb-4dbb-b96c-5116c574a6a2	picture	user.attribute
66230793-eaeb-4dbb-b96c-5116c574a6a2	true	id.token.claim
66230793-eaeb-4dbb-b96c-5116c574a6a2	true	access.token.claim
66230793-eaeb-4dbb-b96c-5116c574a6a2	picture	claim.name
66230793-eaeb-4dbb-b96c-5116c574a6a2	String	jsonType.label
6853ea43-8170-41b2-b5eb-43042da64e40	true	introspection.token.claim
6853ea43-8170-41b2-b5eb-43042da64e40	true	userinfo.token.claim
6853ea43-8170-41b2-b5eb-43042da64e40	locale	user.attribute
6853ea43-8170-41b2-b5eb-43042da64e40	true	id.token.claim
6853ea43-8170-41b2-b5eb-43042da64e40	true	access.token.claim
6853ea43-8170-41b2-b5eb-43042da64e40	locale	claim.name
6853ea43-8170-41b2-b5eb-43042da64e40	String	jsonType.label
7b804119-1f0b-4048-b6a6-00e8af01c4de	true	introspection.token.claim
7b804119-1f0b-4048-b6a6-00e8af01c4de	true	userinfo.token.claim
7b804119-1f0b-4048-b6a6-00e8af01c4de	middleName	user.attribute
7b804119-1f0b-4048-b6a6-00e8af01c4de	true	id.token.claim
7b804119-1f0b-4048-b6a6-00e8af01c4de	true	access.token.claim
7b804119-1f0b-4048-b6a6-00e8af01c4de	middle_name	claim.name
7b804119-1f0b-4048-b6a6-00e8af01c4de	String	jsonType.label
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	true	introspection.token.claim
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	true	userinfo.token.claim
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	nickname	user.attribute
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	true	id.token.claim
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	true	access.token.claim
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	nickname	claim.name
8c750826-ee66-44ee-ba94-7f4fe15ef3c0	String	jsonType.label
9b283cde-ce68-4473-b11f-40eeb9954a39	true	introspection.token.claim
9b283cde-ce68-4473-b11f-40eeb9954a39	true	userinfo.token.claim
9b283cde-ce68-4473-b11f-40eeb9954a39	lastName	user.attribute
9b283cde-ce68-4473-b11f-40eeb9954a39	true	id.token.claim
9b283cde-ce68-4473-b11f-40eeb9954a39	true	access.token.claim
9b283cde-ce68-4473-b11f-40eeb9954a39	family_name	claim.name
9b283cde-ce68-4473-b11f-40eeb9954a39	String	jsonType.label
b1170590-3921-433b-bd7a-69a47c4ccf6a	true	introspection.token.claim
b1170590-3921-433b-bd7a-69a47c4ccf6a	true	userinfo.token.claim
b1170590-3921-433b-bd7a-69a47c4ccf6a	updatedAt	user.attribute
b1170590-3921-433b-bd7a-69a47c4ccf6a	true	id.token.claim
b1170590-3921-433b-bd7a-69a47c4ccf6a	true	access.token.claim
b1170590-3921-433b-bd7a-69a47c4ccf6a	updated_at	claim.name
b1170590-3921-433b-bd7a-69a47c4ccf6a	long	jsonType.label
c6fd97cd-e858-4b4b-ac19-22c453c0b470	true	introspection.token.claim
c6fd97cd-e858-4b4b-ac19-22c453c0b470	true	userinfo.token.claim
c6fd97cd-e858-4b4b-ac19-22c453c0b470	username	user.attribute
c6fd97cd-e858-4b4b-ac19-22c453c0b470	true	id.token.claim
c6fd97cd-e858-4b4b-ac19-22c453c0b470	true	access.token.claim
c6fd97cd-e858-4b4b-ac19-22c453c0b470	preferred_username	claim.name
c6fd97cd-e858-4b4b-ac19-22c453c0b470	String	jsonType.label
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	true	introspection.token.claim
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	true	userinfo.token.claim
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	gender	user.attribute
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	true	id.token.claim
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	true	access.token.claim
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	gender	claim.name
d31b0c97-608c-4e5f-9694-735cbfd0d3a8	String	jsonType.label
d9b607cf-eeef-4ae7-a698-fc23e04bce89	true	introspection.token.claim
d9b607cf-eeef-4ae7-a698-fc23e04bce89	true	userinfo.token.claim
d9b607cf-eeef-4ae7-a698-fc23e04bce89	profile	user.attribute
d9b607cf-eeef-4ae7-a698-fc23e04bce89	true	id.token.claim
d9b607cf-eeef-4ae7-a698-fc23e04bce89	true	access.token.claim
d9b607cf-eeef-4ae7-a698-fc23e04bce89	profile	claim.name
d9b607cf-eeef-4ae7-a698-fc23e04bce89	String	jsonType.label
ed8cba79-1ec0-4260-8135-2710b8d562ab	true	introspection.token.claim
ed8cba79-1ec0-4260-8135-2710b8d562ab	true	userinfo.token.claim
ed8cba79-1ec0-4260-8135-2710b8d562ab	website	user.attribute
ed8cba79-1ec0-4260-8135-2710b8d562ab	true	id.token.claim
ed8cba79-1ec0-4260-8135-2710b8d562ab	true	access.token.claim
ed8cba79-1ec0-4260-8135-2710b8d562ab	website	claim.name
ed8cba79-1ec0-4260-8135-2710b8d562ab	String	jsonType.label
ee0254c2-ad63-422d-94fe-e20ef7048221	true	introspection.token.claim
ee0254c2-ad63-422d-94fe-e20ef7048221	true	userinfo.token.claim
ee0254c2-ad63-422d-94fe-e20ef7048221	birthdate	user.attribute
ee0254c2-ad63-422d-94fe-e20ef7048221	true	id.token.claim
ee0254c2-ad63-422d-94fe-e20ef7048221	true	access.token.claim
ee0254c2-ad63-422d-94fe-e20ef7048221	birthdate	claim.name
ee0254c2-ad63-422d-94fe-e20ef7048221	String	jsonType.label
1b65b2a1-f688-413e-bf54-00c854f4ac0a	true	introspection.token.claim
1b65b2a1-f688-413e-bf54-00c854f4ac0a	true	userinfo.token.claim
1b65b2a1-f688-413e-bf54-00c854f4ac0a	emailVerified	user.attribute
1b65b2a1-f688-413e-bf54-00c854f4ac0a	true	id.token.claim
1b65b2a1-f688-413e-bf54-00c854f4ac0a	true	access.token.claim
1b65b2a1-f688-413e-bf54-00c854f4ac0a	email_verified	claim.name
1b65b2a1-f688-413e-bf54-00c854f4ac0a	boolean	jsonType.label
c78b2e3c-bf20-493c-a095-980d20064d29	true	introspection.token.claim
c78b2e3c-bf20-493c-a095-980d20064d29	true	userinfo.token.claim
c78b2e3c-bf20-493c-a095-980d20064d29	email	user.attribute
c78b2e3c-bf20-493c-a095-980d20064d29	true	id.token.claim
c78b2e3c-bf20-493c-a095-980d20064d29	true	access.token.claim
c78b2e3c-bf20-493c-a095-980d20064d29	email	claim.name
c78b2e3c-bf20-493c-a095-980d20064d29	String	jsonType.label
33247e00-1948-4bde-a5bc-14023dad8e85	formatted	user.attribute.formatted
33247e00-1948-4bde-a5bc-14023dad8e85	country	user.attribute.country
33247e00-1948-4bde-a5bc-14023dad8e85	true	introspection.token.claim
33247e00-1948-4bde-a5bc-14023dad8e85	postal_code	user.attribute.postal_code
33247e00-1948-4bde-a5bc-14023dad8e85	true	userinfo.token.claim
33247e00-1948-4bde-a5bc-14023dad8e85	street	user.attribute.street
33247e00-1948-4bde-a5bc-14023dad8e85	true	id.token.claim
33247e00-1948-4bde-a5bc-14023dad8e85	region	user.attribute.region
33247e00-1948-4bde-a5bc-14023dad8e85	true	access.token.claim
33247e00-1948-4bde-a5bc-14023dad8e85	locality	user.attribute.locality
346312c3-e426-418d-beea-498212b7b8ce	true	introspection.token.claim
346312c3-e426-418d-beea-498212b7b8ce	true	userinfo.token.claim
346312c3-e426-418d-beea-498212b7b8ce	phoneNumberVerified	user.attribute
346312c3-e426-418d-beea-498212b7b8ce	true	id.token.claim
346312c3-e426-418d-beea-498212b7b8ce	true	access.token.claim
346312c3-e426-418d-beea-498212b7b8ce	phone_number_verified	claim.name
346312c3-e426-418d-beea-498212b7b8ce	boolean	jsonType.label
6d5783ed-b4bc-4300-9f81-78aba0962639	true	introspection.token.claim
6d5783ed-b4bc-4300-9f81-78aba0962639	true	userinfo.token.claim
6d5783ed-b4bc-4300-9f81-78aba0962639	phoneNumber	user.attribute
6d5783ed-b4bc-4300-9f81-78aba0962639	true	id.token.claim
6d5783ed-b4bc-4300-9f81-78aba0962639	true	access.token.claim
6d5783ed-b4bc-4300-9f81-78aba0962639	phone_number	claim.name
6d5783ed-b4bc-4300-9f81-78aba0962639	String	jsonType.label
2d9dd7ec-6056-4fb7-b732-a297aae69f5e	true	introspection.token.claim
2d9dd7ec-6056-4fb7-b732-a297aae69f5e	true	access.token.claim
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	true	introspection.token.claim
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	true	multivalued
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	foo	user.attribute
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	true	access.token.claim
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	resource_access.${client_id}.roles	claim.name
9bcdb34b-e90e-41bd-a10b-a08e7a6a4981	String	jsonType.label
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	true	introspection.token.claim
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	true	multivalued
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	foo	user.attribute
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	true	access.token.claim
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	realm_access.roles	claim.name
d1ba05d7-cb5b-4b76-b936-5bd4f6fec2ea	String	jsonType.label
594adb51-bcef-4606-a24f-fa2fbf8ff2bc	true	introspection.token.claim
594adb51-bcef-4606-a24f-fa2fbf8ff2bc	true	access.token.claim
7a3ced81-b07e-45a4-a49e-75d86c3d9030	true	introspection.token.claim
7a3ced81-b07e-45a4-a49e-75d86c3d9030	true	userinfo.token.claim
7a3ced81-b07e-45a4-a49e-75d86c3d9030	username	user.attribute
7a3ced81-b07e-45a4-a49e-75d86c3d9030	true	id.token.claim
7a3ced81-b07e-45a4-a49e-75d86c3d9030	true	access.token.claim
7a3ced81-b07e-45a4-a49e-75d86c3d9030	upn	claim.name
7a3ced81-b07e-45a4-a49e-75d86c3d9030	String	jsonType.label
88492a9d-bad2-4074-a743-13018861f9dd	true	introspection.token.claim
88492a9d-bad2-4074-a743-13018861f9dd	true	multivalued
88492a9d-bad2-4074-a743-13018861f9dd	foo	user.attribute
88492a9d-bad2-4074-a743-13018861f9dd	true	id.token.claim
88492a9d-bad2-4074-a743-13018861f9dd	true	access.token.claim
88492a9d-bad2-4074-a743-13018861f9dd	groups	claim.name
88492a9d-bad2-4074-a743-13018861f9dd	String	jsonType.label
2e713d95-f3c6-446b-bdf8-b3ac5228f653	true	introspection.token.claim
2e713d95-f3c6-446b-bdf8-b3ac5228f653	true	id.token.claim
2e713d95-f3c6-446b-bdf8-b3ac5228f653	true	access.token.claim
51050e6d-9577-4468-915b-fe5e460e1216	true	introspection.token.claim
51050e6d-9577-4468-915b-fe5e460e1216	true	access.token.claim
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	AUTH_TIME	user.session.note
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	true	introspection.token.claim
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	true	id.token.claim
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	true	access.token.claim
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	auth_time	claim.name
e9e868e0-9943-4dc4-a0a7-ed5aecb8b37e	long	jsonType.label
68e24256-c3d8-46aa-845a-d94957ecbd9d	true	introspection.token.claim
68e24256-c3d8-46aa-845a-d94957ecbd9d	true	multivalued
68e24256-c3d8-46aa-845a-d94957ecbd9d	true	id.token.claim
68e24256-c3d8-46aa-845a-d94957ecbd9d	true	access.token.claim
68e24256-c3d8-46aa-845a-d94957ecbd9d	organization	claim.name
68e24256-c3d8-46aa-845a-d94957ecbd9d	String	jsonType.label
a658a2b7-691a-44ef-adb3-7450d1ea1c9b	false	single
a658a2b7-691a-44ef-adb3-7450d1ea1c9b	Basic	attribute.nameformat
a658a2b7-691a-44ef-adb3-7450d1ea1c9b	Role	attribute.name
100293dc-c6b0-4e68-8787-8f5e6aae38e0	true	introspection.token.claim
100293dc-c6b0-4e68-8787-8f5e6aae38e0	true	userinfo.token.claim
100293dc-c6b0-4e68-8787-8f5e6aae38e0	website	user.attribute
100293dc-c6b0-4e68-8787-8f5e6aae38e0	true	id.token.claim
100293dc-c6b0-4e68-8787-8f5e6aae38e0	true	access.token.claim
100293dc-c6b0-4e68-8787-8f5e6aae38e0	website	claim.name
100293dc-c6b0-4e68-8787-8f5e6aae38e0	String	jsonType.label
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	true	introspection.token.claim
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	true	userinfo.token.claim
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	gender	user.attribute
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	true	id.token.claim
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	true	access.token.claim
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	gender	claim.name
17ceff1a-7bc3-49e4-8022-f8d0d3c12f7c	String	jsonType.label
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	true	introspection.token.claim
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	true	userinfo.token.claim
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	lastName	user.attribute
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	true	id.token.claim
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	true	access.token.claim
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	family_name	claim.name
361a86ed-58c1-4ad6-b0f1-f80edc52c9ce	String	jsonType.label
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	true	introspection.token.claim
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	true	userinfo.token.claim
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	updatedAt	user.attribute
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	true	id.token.claim
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	true	access.token.claim
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	updated_at	claim.name
3e126b77-2979-44aa-bdc1-9d7eaa8deb25	long	jsonType.label
5b499ee6-dbae-49d6-806c-20a9ff95c190	true	introspection.token.claim
5b499ee6-dbae-49d6-806c-20a9ff95c190	true	userinfo.token.claim
5b499ee6-dbae-49d6-806c-20a9ff95c190	picture	user.attribute
5b499ee6-dbae-49d6-806c-20a9ff95c190	true	id.token.claim
5b499ee6-dbae-49d6-806c-20a9ff95c190	true	access.token.claim
5b499ee6-dbae-49d6-806c-20a9ff95c190	picture	claim.name
5b499ee6-dbae-49d6-806c-20a9ff95c190	String	jsonType.label
69d3aa65-8947-469a-9f80-a903e7da3634	true	introspection.token.claim
69d3aa65-8947-469a-9f80-a903e7da3634	true	userinfo.token.claim
69d3aa65-8947-469a-9f80-a903e7da3634	true	id.token.claim
69d3aa65-8947-469a-9f80-a903e7da3634	true	access.token.claim
92b8a190-a658-46b8-a076-940ab79d9401	true	introspection.token.claim
92b8a190-a658-46b8-a076-940ab79d9401	true	userinfo.token.claim
92b8a190-a658-46b8-a076-940ab79d9401	profile	user.attribute
92b8a190-a658-46b8-a076-940ab79d9401	true	id.token.claim
92b8a190-a658-46b8-a076-940ab79d9401	true	access.token.claim
92b8a190-a658-46b8-a076-940ab79d9401	profile	claim.name
92b8a190-a658-46b8-a076-940ab79d9401	String	jsonType.label
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	true	introspection.token.claim
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	true	userinfo.token.claim
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	birthdate	user.attribute
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	true	id.token.claim
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	true	access.token.claim
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	birthdate	claim.name
9989e5cd-1c5c-4bad-93c6-3827e887f7e8	String	jsonType.label
a4c12cc6-00e6-4383-b079-eeafd82180ed	true	introspection.token.claim
a4c12cc6-00e6-4383-b079-eeafd82180ed	true	userinfo.token.claim
a4c12cc6-00e6-4383-b079-eeafd82180ed	locale	user.attribute
a4c12cc6-00e6-4383-b079-eeafd82180ed	true	id.token.claim
a4c12cc6-00e6-4383-b079-eeafd82180ed	true	access.token.claim
a4c12cc6-00e6-4383-b079-eeafd82180ed	locale	claim.name
a4c12cc6-00e6-4383-b079-eeafd82180ed	String	jsonType.label
b42afc09-40a2-44ae-86fd-26dcbeed9f35	true	introspection.token.claim
b42afc09-40a2-44ae-86fd-26dcbeed9f35	true	userinfo.token.claim
b42afc09-40a2-44ae-86fd-26dcbeed9f35	middleName	user.attribute
b42afc09-40a2-44ae-86fd-26dcbeed9f35	true	id.token.claim
b42afc09-40a2-44ae-86fd-26dcbeed9f35	true	access.token.claim
b42afc09-40a2-44ae-86fd-26dcbeed9f35	middle_name	claim.name
b42afc09-40a2-44ae-86fd-26dcbeed9f35	String	jsonType.label
b7638da7-ce76-4da0-b1f7-584b63555a53	true	introspection.token.claim
b7638da7-ce76-4da0-b1f7-584b63555a53	true	userinfo.token.claim
b7638da7-ce76-4da0-b1f7-584b63555a53	username	user.attribute
b7638da7-ce76-4da0-b1f7-584b63555a53	true	id.token.claim
b7638da7-ce76-4da0-b1f7-584b63555a53	true	access.token.claim
b7638da7-ce76-4da0-b1f7-584b63555a53	preferred_username	claim.name
b7638da7-ce76-4da0-b1f7-584b63555a53	String	jsonType.label
bec6d813-da36-49a5-adcd-2d97a1df7322	true	introspection.token.claim
bec6d813-da36-49a5-adcd-2d97a1df7322	true	userinfo.token.claim
bec6d813-da36-49a5-adcd-2d97a1df7322	nickname	user.attribute
bec6d813-da36-49a5-adcd-2d97a1df7322	true	id.token.claim
bec6d813-da36-49a5-adcd-2d97a1df7322	true	access.token.claim
bec6d813-da36-49a5-adcd-2d97a1df7322	nickname	claim.name
bec6d813-da36-49a5-adcd-2d97a1df7322	String	jsonType.label
e048153d-2120-4d38-b771-bcec06b3f79d	true	introspection.token.claim
e048153d-2120-4d38-b771-bcec06b3f79d	true	userinfo.token.claim
e048153d-2120-4d38-b771-bcec06b3f79d	firstName	user.attribute
e048153d-2120-4d38-b771-bcec06b3f79d	true	id.token.claim
e048153d-2120-4d38-b771-bcec06b3f79d	true	access.token.claim
e048153d-2120-4d38-b771-bcec06b3f79d	given_name	claim.name
e048153d-2120-4d38-b771-bcec06b3f79d	String	jsonType.label
e9f78452-61bc-49b9-8639-c57836e71cfc	true	introspection.token.claim
e9f78452-61bc-49b9-8639-c57836e71cfc	true	userinfo.token.claim
e9f78452-61bc-49b9-8639-c57836e71cfc	zoneinfo	user.attribute
e9f78452-61bc-49b9-8639-c57836e71cfc	true	id.token.claim
e9f78452-61bc-49b9-8639-c57836e71cfc	true	access.token.claim
e9f78452-61bc-49b9-8639-c57836e71cfc	zoneinfo	claim.name
e9f78452-61bc-49b9-8639-c57836e71cfc	String	jsonType.label
484cd138-5728-4d8c-aae4-e9e103a7ea89	true	introspection.token.claim
484cd138-5728-4d8c-aae4-e9e103a7ea89	true	userinfo.token.claim
484cd138-5728-4d8c-aae4-e9e103a7ea89	email	user.attribute
484cd138-5728-4d8c-aae4-e9e103a7ea89	true	id.token.claim
484cd138-5728-4d8c-aae4-e9e103a7ea89	true	access.token.claim
484cd138-5728-4d8c-aae4-e9e103a7ea89	email	claim.name
484cd138-5728-4d8c-aae4-e9e103a7ea89	String	jsonType.label
a323d623-7b09-44ba-ac4e-07864108776f	true	introspection.token.claim
a323d623-7b09-44ba-ac4e-07864108776f	true	userinfo.token.claim
a323d623-7b09-44ba-ac4e-07864108776f	emailVerified	user.attribute
a323d623-7b09-44ba-ac4e-07864108776f	true	id.token.claim
a323d623-7b09-44ba-ac4e-07864108776f	true	access.token.claim
a323d623-7b09-44ba-ac4e-07864108776f	email_verified	claim.name
a323d623-7b09-44ba-ac4e-07864108776f	boolean	jsonType.label
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	formatted	user.attribute.formatted
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	country	user.attribute.country
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	true	introspection.token.claim
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	postal_code	user.attribute.postal_code
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	true	userinfo.token.claim
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	street	user.attribute.street
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	true	id.token.claim
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	region	user.attribute.region
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	true	access.token.claim
de695591-e2d6-4b86-b5b6-79d03c6fb9fd	locality	user.attribute.locality
a51cbe6b-40d9-4428-8e42-6ce249c234d7	true	introspection.token.claim
a51cbe6b-40d9-4428-8e42-6ce249c234d7	true	userinfo.token.claim
a51cbe6b-40d9-4428-8e42-6ce249c234d7	phoneNumber	user.attribute
a51cbe6b-40d9-4428-8e42-6ce249c234d7	true	id.token.claim
a51cbe6b-40d9-4428-8e42-6ce249c234d7	true	access.token.claim
a51cbe6b-40d9-4428-8e42-6ce249c234d7	phone_number	claim.name
a51cbe6b-40d9-4428-8e42-6ce249c234d7	String	jsonType.label
e5241524-586b-43e0-8a22-90ec12dae96e	true	introspection.token.claim
e5241524-586b-43e0-8a22-90ec12dae96e	true	userinfo.token.claim
e5241524-586b-43e0-8a22-90ec12dae96e	phoneNumberVerified	user.attribute
e5241524-586b-43e0-8a22-90ec12dae96e	true	id.token.claim
e5241524-586b-43e0-8a22-90ec12dae96e	true	access.token.claim
e5241524-586b-43e0-8a22-90ec12dae96e	phone_number_verified	claim.name
e5241524-586b-43e0-8a22-90ec12dae96e	boolean	jsonType.label
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	true	introspection.token.claim
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	true	multivalued
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	foo	user.attribute
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	true	access.token.claim
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	realm_access.roles	claim.name
85c491d8-c0d7-4653-8a3c-856c3d4ec6de	String	jsonType.label
aabe4a00-9dc2-4681-ad02-b588e78a66b5	true	introspection.token.claim
aabe4a00-9dc2-4681-ad02-b588e78a66b5	true	access.token.claim
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	true	introspection.token.claim
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	true	multivalued
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	foo	user.attribute
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	true	access.token.claim
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	resource_access.${client_id}.roles	claim.name
fbfc6bf2-95c8-48ac-b4f7-dc84df5a0955	String	jsonType.label
3b4c4a94-8762-4716-af87-be7f8ff5dc67	true	introspection.token.claim
3b4c4a94-8762-4716-af87-be7f8ff5dc67	true	access.token.claim
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	true	introspection.token.claim
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	true	userinfo.token.claim
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	username	user.attribute
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	true	id.token.claim
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	true	access.token.claim
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	upn	claim.name
59d24e5f-8d9e-44a7-b0de-6a32f7738f1d	String	jsonType.label
60085b44-1cdb-47da-8b91-ceaa60729d47	true	introspection.token.claim
60085b44-1cdb-47da-8b91-ceaa60729d47	true	multivalued
60085b44-1cdb-47da-8b91-ceaa60729d47	foo	user.attribute
60085b44-1cdb-47da-8b91-ceaa60729d47	true	id.token.claim
60085b44-1cdb-47da-8b91-ceaa60729d47	true	access.token.claim
60085b44-1cdb-47da-8b91-ceaa60729d47	groups	claim.name
60085b44-1cdb-47da-8b91-ceaa60729d47	String	jsonType.label
a28c5516-b328-482e-a6a3-4497bb96a38c	true	introspection.token.claim
a28c5516-b328-482e-a6a3-4497bb96a38c	true	id.token.claim
a28c5516-b328-482e-a6a3-4497bb96a38c	true	access.token.claim
1576b4e8-adc4-4dd5-999f-1cca84179345	true	introspection.token.claim
1576b4e8-adc4-4dd5-999f-1cca84179345	true	access.token.claim
e4619dd0-473d-41d2-805f-09c1155fa1c1	AUTH_TIME	user.session.note
e4619dd0-473d-41d2-805f-09c1155fa1c1	true	introspection.token.claim
e4619dd0-473d-41d2-805f-09c1155fa1c1	true	id.token.claim
e4619dd0-473d-41d2-805f-09c1155fa1c1	true	access.token.claim
e4619dd0-473d-41d2-805f-09c1155fa1c1	auth_time	claim.name
e4619dd0-473d-41d2-805f-09c1155fa1c1	long	jsonType.label
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	true	introspection.token.claim
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	true	multivalued
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	true	id.token.claim
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	true	access.token.claim
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	organization	claim.name
0bb6f0c2-fd4e-4af9-ad09-17e4b91bd498	String	jsonType.label
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	true	introspection.token.claim
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	true	userinfo.token.claim
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	locale	user.attribute
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	true	id.token.claim
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	true	access.token.claim
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	locale	claim.name
bf7064ba-9624-49fd-ab18-2bb321a0b0c6	String	jsonType.label
\.


--
-- Data for Name: realm; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm (id, access_code_lifespan, user_action_lifespan, access_token_lifespan, account_theme, admin_theme, email_theme, enabled, events_enabled, events_expiration, login_theme, name, not_before, password_policy, registration_allowed, remember_me, reset_password_allowed, social, ssl_required, sso_idle_timeout, sso_max_lifespan, update_profile_on_soc_login, verify_email, master_admin_client, login_lifespan, internationalization_enabled, default_locale, reg_email_as_username, admin_events_enabled, admin_events_details_enabled, edit_username_allowed, otp_policy_counter, otp_policy_window, otp_policy_period, otp_policy_digits, otp_policy_alg, otp_policy_type, browser_flow, registration_flow, direct_grant_flow, reset_credentials_flow, client_auth_flow, offline_session_idle_timeout, revoke_refresh_token, access_token_life_implicit, login_with_email_allowed, duplicate_emails_allowed, docker_auth_flow, refresh_token_max_reuse, allow_user_managed_access, sso_max_lifespan_remember_me, sso_idle_timeout_remember_me, default_role) FROM stdin;
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	60	300	300	keycloak.v3	keycloak.v2	keycloak	t	f	0	keycloak.v2	Test	0	\N	t	t	t	f	EXTERNAL	1800	43200	f	f	e927bf1e-34ba-4182-9815-66a5c84b7a23	1800	f	\N	t	f	f	f	0	1	30	6	HmacSHA1	totp	3ac63505-a8ac-4176-815a-fa38d513c145	2bda16cd-a2ee-4899-9281-01120e271f39	adabb682-8fe5-4142-a1ce-59c7e8219470	042e46e8-c183-4d61-8b08-ba48ceb00fd1	65c30146-5469-4da5-a010-dfad5eee7fdd	2592000	f	900	t	f	9da04634-988c-46aa-b2cd-a32be33ac91f	0	f	0	0	3c4a339d-6f51-4bd0-89ae-6df6717752b1
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	60	300	60	keycloak.v3	keycloak.v2	keycloak	t	f	0	keycloak.v2	master	0	\N	t	t	t	f	EXTERNAL	1800	36000	f	f	da4c211e-5148-4471-8884-d95420b88548	1800	f	\N	f	f	f	f	0	1	30	6	HmacSHA1	totp	78446504-0b4c-4af0-ad14-873219332369	c999d09a-a3df-4fc0-9363-f53186cbf71a	e0d57b8a-61c5-4c6d-82fc-1d1c3b1a3cf6	2557231a-a634-4c1d-a7f1-1992cfa00924	d4128574-8dfe-42ed-b9d9-d032451a6828	2592000	f	900	t	f	028aa2e6-43d2-4060-829c-72c105543119	0	f	0	0	1300e97a-2599-431d-8169-937df66ace29
\.


--
-- Data for Name: realm_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_attribute (name, realm_id, value) FROM stdin;
bruteForceProtected	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
permanentLockout	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
maxTemporaryLockouts	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
maxFailureWaitSeconds	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	900
minimumQuickLoginWaitSeconds	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	60
waitIncrementSeconds	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	60
quickLoginCheckMilliSeconds	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	1000
maxDeltaTimeSeconds	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	43200
failureFactor	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	30
realmReusableOtpCode	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
firstBrokerLoginFlowId	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	c13a3512-6b0e-4198-8f81-6dacf5d80d57
displayName	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	Keycloak
displayNameHtml	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	<div class="kc-logo-text"><span>Keycloak</span></div>
defaultSignatureAlgorithm	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	RS256
offlineSessionMaxLifespanEnabled	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
offlineSessionMaxLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	5184000
bruteForceProtected	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
permanentLockout	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
maxTemporaryLockouts	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
maxFailureWaitSeconds	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	900
minimumQuickLoginWaitSeconds	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	60
waitIncrementSeconds	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	60
quickLoginCheckMilliSeconds	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	1000
maxDeltaTimeSeconds	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	43200
failureFactor	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	30
realmReusableOtpCode	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
defaultSignatureAlgorithm	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	RS256
offlineSessionMaxLifespanEnabled	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
offlineSessionMaxLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	5184000
actionTokenGeneratedByAdminLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	43200
actionTokenGeneratedByUserLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	300
oauth2DeviceCodeLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	600
oauth2DevicePollingInterval	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	5
webAuthnPolicyRpEntityName	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	keycloak
webAuthnPolicySignatureAlgorithms	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	ES256,RS256
webAuthnPolicyRpId	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	
webAuthnPolicyAttestationConveyancePreference	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyAuthenticatorAttachment	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyRequireResidentKey	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyUserVerificationRequirement	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyCreateTimeout	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
webAuthnPolicyAvoidSameAuthenticatorRegister	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
webAuthnPolicyRpEntityNamePasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	keycloak
webAuthnPolicySignatureAlgorithmsPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	ES256,RS256
webAuthnPolicyRpIdPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	
webAuthnPolicyAttestationConveyancePreferencePasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyAuthenticatorAttachmentPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyRequireResidentKeyPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyUserVerificationRequirementPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	not specified
webAuthnPolicyCreateTimeoutPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
cibaBackchannelTokenDeliveryMode	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	poll
cibaExpiresIn	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	120
cibaInterval	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	5
cibaAuthRequestedUserHint	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	login_hint
parRequestUriLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	60
firstBrokerLoginFlowId	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	e840cd3c-8a7c-408b-a232-efd488fbe293
organizationsEnabled	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	false
clientSessionIdleTimeout	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
clientSessionMaxLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
clientOfflineSessionIdleTimeout	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
clientOfflineSessionMaxLifespan	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	0
client-policies.profiles	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	{"profiles":[]}
client-policies.policies	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	{"policies":[]}
_browser_header.contentSecurityPolicyReportOnly	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	
_browser_header.xContentTypeOptions	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	nosniff
_browser_header.referrerPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	no-referrer
_browser_header.xRobotsTag	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	none
_browser_header.xFrameOptions	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	SAMEORIGIN
_browser_header.contentSecurityPolicy	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	frame-src 'self'; frame-ancestors 'self'; object-src 'none';
_browser_header.xXSSProtection	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	1; mode=block
_browser_header.strictTransportSecurity	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	max-age=31536000; includeSubDomains
cibaBackchannelTokenDeliveryMode	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	poll
cibaExpiresIn	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	120
cibaAuthRequestedUserHint	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	login_hint
parRequestUriLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	60
cibaInterval	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	5
organizationsEnabled	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
actionTokenGeneratedByAdminLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	43200
actionTokenGeneratedByUserLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	300
oauth2DeviceCodeLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	600
oauth2DevicePollingInterval	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	5
clientSessionIdleTimeout	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
clientSessionMaxLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
clientOfflineSessionIdleTimeout	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
clientOfflineSessionMaxLifespan	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
webAuthnPolicyRpEntityName	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	keycloak
webAuthnPolicySignatureAlgorithms	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	ES256,RS256
webAuthnPolicyRpId	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	
webAuthnPolicyAttestationConveyancePreference	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyAuthenticatorAttachment	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyRequireResidentKey	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyUserVerificationRequirement	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyCreateTimeout	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
webAuthnPolicyAvoidSameAuthenticatorRegister	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
webAuthnPolicyRpEntityNamePasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	keycloak
webAuthnPolicySignatureAlgorithmsPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	ES256,RS256
webAuthnPolicyRpIdPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	
webAuthnPolicyAttestationConveyancePreferencePasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyAuthenticatorAttachmentPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyRequireResidentKeyPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyUserVerificationRequirementPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	not specified
webAuthnPolicyCreateTimeoutPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	0
webAuthnPolicyAvoidSameAuthenticatorRegisterPasswordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	false
client-policies.profiles	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	{"profiles":[]}
client-policies.policies	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	{"policies":[]}
_browser_header.contentSecurityPolicyReportOnly	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	
_browser_header.xContentTypeOptions	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	nosniff
_browser_header.referrerPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	no-referrer
_browser_header.xRobotsTag	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	none
_browser_header.xFrameOptions	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	SAMEORIGIN
_browser_header.contentSecurityPolicy	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	frame-src 'self'; frame-ancestors 'self'; object-src 'none';
_browser_header.xXSSProtection	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	1; mode=block
_browser_header.strictTransportSecurity	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	max-age=31536000; includeSubDomains
\.


--
-- Data for Name: realm_default_groups; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_default_groups (realm_id, group_id) FROM stdin;
\.


--
-- Data for Name: realm_enabled_event_types; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_enabled_event_types (realm_id, value) FROM stdin;
\.


--
-- Data for Name: realm_events_listeners; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_events_listeners (realm_id, value) FROM stdin;
1fd1d65f-fda3-4eb2-9093-366dc2f226ac	jboss-logging
cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	jboss-logging
\.


--
-- Data for Name: realm_localizations; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_localizations (realm_id, locale, texts) FROM stdin;
\.


--
-- Data for Name: realm_required_credential; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_required_credential (type, form_label, input, secret, realm_id) FROM stdin;
password	password	t	t	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f
password	password	t	t	1fd1d65f-fda3-4eb2-9093-366dc2f226ac
\.


--
-- Data for Name: realm_smtp_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_smtp_config (realm_id, value, name) FROM stdin;
\.


--
-- Data for Name: realm_supported_locales; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.realm_supported_locales (realm_id, value) FROM stdin;
\.


--
-- Data for Name: redirect_uris; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.redirect_uris (client_id, value) FROM stdin;
6125bc74-bea8-40b9-b320-d88778d34fba	/realms/master/account/*
66a0b273-0636-4348-8af9-896341a374ed	/realms/master/account/*
1fec1117-a310-4f9d-9373-1c76e8b7d64b	/admin/master/console/*
6f74340e-b12f-46cb-b362-f59b37cc8930	/realms/Test/account/*
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	/realms/Test/account/*
09c0b19b-3328-44b8-b0d5-983e6b4b358e	/admin/Test/console/*
\.


--
-- Data for Name: required_action_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.required_action_config (required_action_id, value, name) FROM stdin;
\.


--
-- Data for Name: required_action_provider; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.required_action_provider (id, alias, name, realm_id, enabled, default_action, provider_id, priority) FROM stdin;
9768e524-61d8-4910-bf1d-010032488ead	TERMS_AND_CONDITIONS	Terms and Conditions	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	TERMS_AND_CONDITIONS	20
827adb33-a77b-4a97-bb1a-beb9d1521259	delete_account	Delete Account	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	delete_account	60
60c990e2-ff39-40d6-a665-26878211f239	UPDATE_PASSWORD	Update Password	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	t	f	UPDATE_PASSWORD	30
422e207e-32df-417c-ac06-fca9a5068b12	TERMS_AND_CONDITIONS	Terms and Conditions	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	TERMS_AND_CONDITIONS	20
db1682ac-4f61-435a-8be3-da182f9c9b00	delete_account	Delete Account	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	delete_account	60
08691917-af3a-4edb-9a4a-11e3f42bccc5	webauthn-register	Webauthn Register	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	t	f	webauthn-register	70
45dcc0c5-2aa6-4f47-bad5-0868a1f9f566	CONFIGURE_TOTP	Configure OTP	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	CONFIGURE_TOTP	10
5d650867-f9c8-4f45-b575-c9db4d31e16f	VERIFY_EMAIL	Verify Email	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	VERIFY_EMAIL	50
3cd063df-2d42-467d-a6e3-77eb678238a7	UPDATE_PROFILE	Update Profile	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	UPDATE_PROFILE	40
8f20d886-4772-4430-a6d7-1b44408355c1	webauthn-register-passwordless	Webauthn Register Passwordless	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	webauthn-register-passwordless	80
6d32c74f-fdf6-4fd0-b95a-3e082fbfbea0	delete_credential	Delete Credential	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	delete_credential	100
25ef8805-ac7d-4878-af65-cd14eb5704b3	VERIFY_PROFILE	Verify Profile	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	VERIFY_PROFILE	90
58e8f94e-5de2-4294-b67e-21f119871e0a	update_user_locale	Update User Locale	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	f	f	update_user_locale	1000
5c226497-d5b5-4c73-8301-318c89a76273	CONFIGURE_TOTP	Configure OTP	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	CONFIGURE_TOTP	10
60125c50-775f-4115-a99c-afc9455654bc	UPDATE_PASSWORD	Update Password	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	UPDATE_PASSWORD	30
708f207b-a526-4183-be92-0029f3a7b4e2	VERIFY_EMAIL	Verify Email	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	VERIFY_EMAIL	50
7c4c7a43-61aa-4b95-854c-618fded3835e	webauthn-register	Webauthn Register	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	webauthn-register	70
4c0f07e0-5292-40e0-8057-7bd8752d1bee	webauthn-register-passwordless	Webauthn Register Passwordless	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	webauthn-register-passwordless	80
d48753f4-03fc-4e7a-a4a0-fe6ca31fadf8	VERIFY_PROFILE	Verify Profile	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	VERIFY_PROFILE	90
7e4856d9-0c28-4950-bf60-f7061e1d792b	delete_credential	Delete Credential	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	delete_credential	100
97143435-8fd9-4cd7-838d-1f1c4b3ebe90	update_user_locale	Update User Locale	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	f	f	update_user_locale	1000
df4ad674-0553-4625-a019-3e08cd903a11	UPDATE_PROFILE	Update Profile	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	t	t	UPDATE_PROFILE	40
\.


--
-- Data for Name: resource_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_attribute (id, name, value, resource_id) FROM stdin;
\.


--
-- Data for Name: resource_policy; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_policy (resource_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_scope (resource_id, scope_id) FROM stdin;
\.


--
-- Data for Name: resource_server; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_server (id, allow_rs_remote_mgmt, policy_enforce_mode, decision_strategy) FROM stdin;
\.


--
-- Data for Name: resource_server_perm_ticket; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_server_perm_ticket (id, owner, requester, created_timestamp, granted_timestamp, resource_id, scope_id, resource_server_id, policy_id) FROM stdin;
\.


--
-- Data for Name: resource_server_policy; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_server_policy (id, name, description, type, decision_strategy, logic, resource_server_id, owner) FROM stdin;
\.


--
-- Data for Name: resource_server_resource; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_server_resource (id, name, type, icon_uri, owner, resource_server_id, owner_managed_access, display_name) FROM stdin;
\.


--
-- Data for Name: resource_server_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_server_scope (id, name, icon_uri, resource_server_id, display_name) FROM stdin;
\.


--
-- Data for Name: resource_uris; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.resource_uris (resource_id, value) FROM stdin;
\.


--
-- Data for Name: revoked_token; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.revoked_token (id, expire) FROM stdin;
\.


--
-- Data for Name: role_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.role_attribute (id, role_id, name, value) FROM stdin;
\.


--
-- Data for Name: scope_mapping; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.scope_mapping (client_id, role_id) FROM stdin;
66a0b273-0636-4348-8af9-896341a374ed	c3612af0-a78d-4863-bc60-cfee5b0471c1
66a0b273-0636-4348-8af9-896341a374ed	8d03dc4f-0cbf-442a-8e16-11d55235baf8
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	3872bf40-d0af-4bd6-a810-e312d722fce5
d193cc0b-5a5e-44a8-8003-9bcf5828a59f	3371bb12-52d1-4542-a96e-0a9dac54e424
\.


--
-- Data for Name: scope_policy; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.scope_policy (scope_id, policy_id) FROM stdin;
\.


--
-- Data for Name: user_attribute; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_attribute (name, value, user_id, id, long_value_hash, long_value_hash_lower_case, long_value) FROM stdin;
\.


--
-- Data for Name: user_consent; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_consent (id, client_id, user_id, created_date, last_updated_date, client_storage_provider, external_client_id) FROM stdin;
\.


--
-- Data for Name: user_consent_client_scope; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_consent_client_scope (user_consent_id, scope_id) FROM stdin;
\.


--
-- Data for Name: user_entity; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_entity (id, email, email_constraint, email_verified, enabled, federation_link, first_name, last_name, realm_id, username, created_timestamp, service_account_client_link, not_before) FROM stdin;
3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8	root@goblin.com	root@goblin.com	t	t	\N	\N	\N	1fd1d65f-fda3-4eb2-9093-366dc2f226ac	root@goblin.com	1729024351950	\N	0
d5b2a49e-edef-49c1-961f-5d4e562a7659	root@root.com	root@root.com	t	t	\N	Mos	Moska	cb17e273-ed97-49ed-9ef0-6e6c1dfa4a7f	root	1729025094398	\N	0
\.


--
-- Data for Name: user_federation_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_federation_config (user_federation_provider_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_federation_mapper (id, name, federation_provider_id, federation_mapper_type, realm_id) FROM stdin;
\.


--
-- Data for Name: user_federation_mapper_config; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_federation_mapper_config (user_federation_mapper_id, value, name) FROM stdin;
\.


--
-- Data for Name: user_federation_provider; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_federation_provider (id, changed_sync_period, display_name, full_sync_period, last_sync, priority, provider_name, realm_id) FROM stdin;
\.


--
-- Data for Name: user_group_membership; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_group_membership (group_id, user_id, membership_type) FROM stdin;
\.


--
-- Data for Name: user_required_action; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_required_action (user_id, required_action) FROM stdin;
\.


--
-- Data for Name: user_role_mapping; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.user_role_mapping (role_id, user_id) FROM stdin;
3c4a339d-6f51-4bd0-89ae-6df6717752b1	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
cca7428b-0082-4284-9ce3-fe103d6daaf7	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
12f21043-1b94-4d7c-a025-00dbd116a903	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
cbe2a382-5d41-456e-8238-0e5c4cd023c8	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
a2a94e10-852a-4beb-abd9-c56db1904bba	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
096d3e08-2423-48f4-8038-57ea467aea9d	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
3371bb12-52d1-4542-a96e-0a9dac54e424	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
8dbf782d-4c54-4083-92f5-0055148ffeb9	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
4ccbdbd2-b97d-4a37-8173-5dda28f12750	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
7ca13251-2fdc-4a27-9318-c5db26e0a813	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
ce68637a-57d6-4bb2-ab5d-5db0ce0d5f0d	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
3872bf40-d0af-4bd6-a810-e312d722fce5	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
f26c857f-0a8f-4112-8b0c-cefa11978f2b	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
13628d05-9caf-480c-ae1c-92ea26de42b1	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
60e4c13b-fba2-4c49-a17f-d606f0595e9a	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
daf5d3a9-cef3-41d8-b4e3-e6ebe5d7bfa1	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
316c8c11-5140-45dc-9790-6f262c7a92f2	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
3bb70329-f2bd-4800-bd67-654ab12a9bc6	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
2ad3a054-c1a8-4b78-8a82-6a9469cae5d3	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
6274cab9-6eab-42fa-aabd-bac08d5309f4	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
4025a7c7-b45c-4478-8da1-6e046124a4ef	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
7fb645d9-8a53-456f-8ea9-a2cabc80dac3	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
3641a812-b9e4-4822-95d4-eea7d8810ba0	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
994af3d5-88c3-4abc-9d25-67e0ac50fe06	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
2e73f013-7426-4021-baaf-2023c2bd4b52	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
792be8d1-a9a3-4746-8985-ca265f0a1d90	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
a3110636-4295-4e5d-aacd-09625d2e446a	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
8d47f7ec-68c8-4ee1-8d2c-9bd9c120eeba	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
8382deaa-a5f7-42e4-815b-460b09931bbf	3b71ff7b-2f57-4cbb-aa19-2ece5185c6d8
1300e97a-2599-431d-8169-937df66ace29	d5b2a49e-edef-49c1-961f-5d4e562a7659
022cbd46-4ad6-45e2-8f9c-b9d7b1b14b24	d5b2a49e-edef-49c1-961f-5d4e562a7659
73a8cfb4-2f8d-4e71-a383-c59f23015994	d5b2a49e-edef-49c1-961f-5d4e562a7659
67e69687-c5af-422f-9c6d-dd9ca6064817	d5b2a49e-edef-49c1-961f-5d4e562a7659
251e2a5f-279a-4f24-a4a9-84ecb1afc201	d5b2a49e-edef-49c1-961f-5d4e562a7659
\.


--
-- Data for Name: username_login_failure; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.username_login_failure (realm_id, username, failed_login_not_before, last_failure, last_ip_failure, num_failures) FROM stdin;
\.


--
-- Data for Name: web_origins; Type: TABLE DATA; Schema: public; Owner: admin
--

COPY public.web_origins (client_id, value) FROM stdin;
1fec1117-a310-4f9d-9373-1c76e8b7d64b	+
09c0b19b-3328-44b8-b0d5-983e6b4b358e	+
\.


--
-- Name: username_login_failure CONSTRAINT_17-2; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.username_login_failure
    ADD CONSTRAINT "CONSTRAINT_17-2" PRIMARY KEY (realm_id, username);


--
-- Name: org_domain ORG_DOMAIN_pkey; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.org_domain
    ADD CONSTRAINT "ORG_DOMAIN_pkey" PRIMARY KEY (id, name);


--
-- Name: org ORG_pkey; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT "ORG_pkey" PRIMARY KEY (id);


--
-- Name: keycloak_role UK_J3RWUVD56ONTGSUHOGM184WW2-2; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT "UK_J3RWUVD56ONTGSUHOGM184WW2-2" UNIQUE (name, client_realm_constraint);


--
-- Name: client_auth_flow_bindings c_cli_flow_bind; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_auth_flow_bindings
    ADD CONSTRAINT c_cli_flow_bind PRIMARY KEY (client_id, binding_name);


--
-- Name: client_scope_client c_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope_client
    ADD CONSTRAINT c_cli_scope_bind PRIMARY KEY (client_id, scope_id);


--
-- Name: client_initial_access cnstr_client_init_acc_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT cnstr_client_init_acc_pk PRIMARY KEY (id);


--
-- Name: realm_default_groups con_group_id_def_groups; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT con_group_id_def_groups UNIQUE (group_id);


--
-- Name: broker_link constr_broker_link_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.broker_link
    ADD CONSTRAINT constr_broker_link_pk PRIMARY KEY (identity_provider, user_id);


--
-- Name: component_config constr_component_config_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT constr_component_config_pk PRIMARY KEY (id);


--
-- Name: component constr_component_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT constr_component_pk PRIMARY KEY (id);


--
-- Name: fed_user_required_action constr_fed_required_action; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_required_action
    ADD CONSTRAINT constr_fed_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: fed_user_attribute constr_fed_user_attr_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_attribute
    ADD CONSTRAINT constr_fed_user_attr_pk PRIMARY KEY (id);


--
-- Name: fed_user_consent constr_fed_user_consent_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_consent
    ADD CONSTRAINT constr_fed_user_consent_pk PRIMARY KEY (id);


--
-- Name: fed_user_credential constr_fed_user_cred_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_credential
    ADD CONSTRAINT constr_fed_user_cred_pk PRIMARY KEY (id);


--
-- Name: fed_user_group_membership constr_fed_user_group; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_group_membership
    ADD CONSTRAINT constr_fed_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: fed_user_role_mapping constr_fed_user_role; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_role_mapping
    ADD CONSTRAINT constr_fed_user_role PRIMARY KEY (role_id, user_id);


--
-- Name: federated_user constr_federated_user; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.federated_user
    ADD CONSTRAINT constr_federated_user PRIMARY KEY (id);


--
-- Name: realm_default_groups constr_realm_default_groups; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT constr_realm_default_groups PRIMARY KEY (realm_id, group_id);


--
-- Name: realm_enabled_event_types constr_realm_enabl_event_types; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT constr_realm_enabl_event_types PRIMARY KEY (realm_id, value);


--
-- Name: realm_events_listeners constr_realm_events_listeners; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT constr_realm_events_listeners PRIMARY KEY (realm_id, value);


--
-- Name: realm_supported_locales constr_realm_supported_locales; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT constr_realm_supported_locales PRIMARY KEY (realm_id, value);


--
-- Name: identity_provider constraint_2b; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT constraint_2b PRIMARY KEY (internal_id);


--
-- Name: client_attributes constraint_3c; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT constraint_3c PRIMARY KEY (client_id, name);


--
-- Name: event_entity constraint_4; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.event_entity
    ADD CONSTRAINT constraint_4 PRIMARY KEY (id);


--
-- Name: federated_identity constraint_40; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT constraint_40 PRIMARY KEY (identity_provider, user_id);


--
-- Name: realm constraint_4a; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT constraint_4a PRIMARY KEY (id);


--
-- Name: user_federation_provider constraint_5c; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT constraint_5c PRIMARY KEY (id);


--
-- Name: client constraint_7; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT constraint_7 PRIMARY KEY (id);


--
-- Name: scope_mapping constraint_81; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT constraint_81 PRIMARY KEY (client_id, role_id);


--
-- Name: client_node_registrations constraint_84; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT constraint_84 PRIMARY KEY (client_id, name);


--
-- Name: realm_attribute constraint_9; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT constraint_9 PRIMARY KEY (name, realm_id);


--
-- Name: realm_required_credential constraint_92; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT constraint_92 PRIMARY KEY (realm_id, type);


--
-- Name: keycloak_role constraint_a; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT constraint_a PRIMARY KEY (id);


--
-- Name: admin_event_entity constraint_admin_event_entity; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.admin_event_entity
    ADD CONSTRAINT constraint_admin_event_entity PRIMARY KEY (id);


--
-- Name: authenticator_config_entry constraint_auth_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authenticator_config_entry
    ADD CONSTRAINT constraint_auth_cfg_pk PRIMARY KEY (authenticator_id, name);


--
-- Name: authentication_execution constraint_auth_exec_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT constraint_auth_exec_pk PRIMARY KEY (id);


--
-- Name: authentication_flow constraint_auth_flow_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT constraint_auth_flow_pk PRIMARY KEY (id);


--
-- Name: authenticator_config constraint_auth_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT constraint_auth_pk PRIMARY KEY (id);


--
-- Name: user_role_mapping constraint_c; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT constraint_c PRIMARY KEY (role_id, user_id);


--
-- Name: composite_role constraint_composite_role; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT constraint_composite_role PRIMARY KEY (composite, child_role);


--
-- Name: identity_provider_config constraint_d; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT constraint_d PRIMARY KEY (identity_provider_id, name);


--
-- Name: policy_config constraint_dpc; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT constraint_dpc PRIMARY KEY (policy_id, name);


--
-- Name: realm_smtp_config constraint_e; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT constraint_e PRIMARY KEY (realm_id, name);


--
-- Name: credential constraint_f; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT constraint_f PRIMARY KEY (id);


--
-- Name: user_federation_config constraint_f9; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT constraint_f9 PRIMARY KEY (user_federation_provider_id, name);


--
-- Name: resource_server_perm_ticket constraint_fapmt; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT constraint_fapmt PRIMARY KEY (id);


--
-- Name: resource_server_resource constraint_farsr; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT constraint_farsr PRIMARY KEY (id);


--
-- Name: resource_server_policy constraint_farsrp; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT constraint_farsrp PRIMARY KEY (id);


--
-- Name: associated_policy constraint_farsrpap; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT constraint_farsrpap PRIMARY KEY (policy_id, associated_policy_id);


--
-- Name: resource_policy constraint_farsrpp; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT constraint_farsrpp PRIMARY KEY (resource_id, policy_id);


--
-- Name: resource_server_scope constraint_farsrs; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT constraint_farsrs PRIMARY KEY (id);


--
-- Name: resource_scope constraint_farsrsp; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT constraint_farsrsp PRIMARY KEY (resource_id, scope_id);


--
-- Name: scope_policy constraint_farsrsps; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT constraint_farsrsps PRIMARY KEY (scope_id, policy_id);


--
-- Name: user_entity constraint_fb; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT constraint_fb PRIMARY KEY (id);


--
-- Name: user_federation_mapper_config constraint_fedmapper_cfg_pm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT constraint_fedmapper_cfg_pm PRIMARY KEY (user_federation_mapper_id, name);


--
-- Name: user_federation_mapper constraint_fedmapperpm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT constraint_fedmapperpm PRIMARY KEY (id);


--
-- Name: fed_user_consent_cl_scope constraint_fgrntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.fed_user_consent_cl_scope
    ADD CONSTRAINT constraint_fgrntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent_client_scope constraint_grntcsnt_clsc_pm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT constraint_grntcsnt_clsc_pm PRIMARY KEY (user_consent_id, scope_id);


--
-- Name: user_consent constraint_grntcsnt_pm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT constraint_grntcsnt_pm PRIMARY KEY (id);


--
-- Name: keycloak_group constraint_group; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT constraint_group PRIMARY KEY (id);


--
-- Name: group_attribute constraint_group_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT constraint_group_attribute_pk PRIMARY KEY (id);


--
-- Name: group_role_mapping constraint_group_role; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT constraint_group_role PRIMARY KEY (role_id, group_id);


--
-- Name: identity_provider_mapper constraint_idpm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT constraint_idpm PRIMARY KEY (id);


--
-- Name: idp_mapper_config constraint_idpmconfig; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT constraint_idpmconfig PRIMARY KEY (idp_mapper_id, name);


--
-- Name: migration_model constraint_migmod; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.migration_model
    ADD CONSTRAINT constraint_migmod PRIMARY KEY (id);


--
-- Name: offline_client_session constraint_offl_cl_ses_pk3; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.offline_client_session
    ADD CONSTRAINT constraint_offl_cl_ses_pk3 PRIMARY KEY (user_session_id, client_id, client_storage_provider, external_client_id, offline_flag);


--
-- Name: offline_user_session constraint_offl_us_ses_pk2; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.offline_user_session
    ADD CONSTRAINT constraint_offl_us_ses_pk2 PRIMARY KEY (user_session_id, offline_flag);


--
-- Name: protocol_mapper constraint_pcm; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT constraint_pcm PRIMARY KEY (id);


--
-- Name: protocol_mapper_config constraint_pmconfig; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT constraint_pmconfig PRIMARY KEY (protocol_mapper_id, name);


--
-- Name: redirect_uris constraint_redirect_uris; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT constraint_redirect_uris PRIMARY KEY (client_id, value);


--
-- Name: required_action_config constraint_req_act_cfg_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.required_action_config
    ADD CONSTRAINT constraint_req_act_cfg_pk PRIMARY KEY (required_action_id, name);


--
-- Name: required_action_provider constraint_req_act_prv_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT constraint_req_act_prv_pk PRIMARY KEY (id);


--
-- Name: user_required_action constraint_required_action; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT constraint_required_action PRIMARY KEY (required_action, user_id);


--
-- Name: resource_uris constraint_resour_uris_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT constraint_resour_uris_pk PRIMARY KEY (resource_id, value);


--
-- Name: role_attribute constraint_role_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT constraint_role_attribute_pk PRIMARY KEY (id);


--
-- Name: revoked_token constraint_rt; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.revoked_token
    ADD CONSTRAINT constraint_rt PRIMARY KEY (id);


--
-- Name: user_attribute constraint_user_attribute_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT constraint_user_attribute_pk PRIMARY KEY (id);


--
-- Name: user_group_membership constraint_user_group; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT constraint_user_group PRIMARY KEY (group_id, user_id);


--
-- Name: web_origins constraint_web_origins; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT constraint_web_origins PRIMARY KEY (client_id, value);


--
-- Name: databasechangeloglock databasechangeloglock_pkey; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.databasechangeloglock
    ADD CONSTRAINT databasechangeloglock_pkey PRIMARY KEY (id);


--
-- Name: client_scope_attributes pk_cl_tmpl_attr; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT pk_cl_tmpl_attr PRIMARY KEY (scope_id, name);


--
-- Name: client_scope pk_cli_template; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT pk_cli_template PRIMARY KEY (id);


--
-- Name: resource_server pk_resource_server; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server
    ADD CONSTRAINT pk_resource_server PRIMARY KEY (id);


--
-- Name: client_scope_role_mapping pk_template_scope; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT pk_template_scope PRIMARY KEY (scope_id, role_id);


--
-- Name: default_client_scope r_def_cli_scope_bind; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT r_def_cli_scope_bind PRIMARY KEY (realm_id, scope_id);


--
-- Name: realm_localizations realm_localizations_pkey; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_localizations
    ADD CONSTRAINT realm_localizations_pkey PRIMARY KEY (realm_id, locale);


--
-- Name: resource_attribute res_attr_pk; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT res_attr_pk PRIMARY KEY (id);


--
-- Name: keycloak_group sibling_names; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.keycloak_group
    ADD CONSTRAINT sibling_names UNIQUE (realm_id, parent_group, name);


--
-- Name: identity_provider uk_2daelwnibji49avxsrtuf6xj33; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT uk_2daelwnibji49avxsrtuf6xj33 UNIQUE (provider_alias, realm_id);


--
-- Name: client uk_b71cjlbenv945rb6gcon438at; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client
    ADD CONSTRAINT uk_b71cjlbenv945rb6gcon438at UNIQUE (realm_id, client_id);


--
-- Name: client_scope uk_cli_scope; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope
    ADD CONSTRAINT uk_cli_scope UNIQUE (realm_id, name);


--
-- Name: user_entity uk_dykn684sl8up1crfei6eckhd7; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_dykn684sl8up1crfei6eckhd7 UNIQUE (realm_id, email_constraint);


--
-- Name: user_consent uk_external_consent; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_external_consent UNIQUE (client_storage_provider, external_client_id, user_id);


--
-- Name: resource_server_resource uk_frsr6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5ha6 UNIQUE (name, owner, resource_server_id);


--
-- Name: resource_server_perm_ticket uk_frsr6t700s9v50bu18ws5pmt; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT uk_frsr6t700s9v50bu18ws5pmt UNIQUE (owner, requester, resource_server_id, resource_id, scope_id);


--
-- Name: resource_server_policy uk_frsrpt700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT uk_frsrpt700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: resource_server_scope uk_frsrst700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT uk_frsrst700s9v50bu18ws5ha6 UNIQUE (name, resource_server_id);


--
-- Name: user_consent uk_local_consent; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT uk_local_consent UNIQUE (client_id, user_id);


--
-- Name: org uk_org_alias; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_alias UNIQUE (realm_id, alias);


--
-- Name: org uk_org_group; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_group UNIQUE (group_id);


--
-- Name: org uk_org_name; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.org
    ADD CONSTRAINT uk_org_name UNIQUE (realm_id, name);


--
-- Name: realm uk_orvsdmla56612eaefiq6wl5oi; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm
    ADD CONSTRAINT uk_orvsdmla56612eaefiq6wl5oi UNIQUE (name);


--
-- Name: user_entity uk_ru8tt6t700s9v50bu18ws5ha6; Type: CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_entity
    ADD CONSTRAINT uk_ru8tt6t700s9v50bu18ws5ha6 UNIQUE (realm_id, username);


--
-- Name: fed_user_attr_long_values; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX fed_user_attr_long_values ON public.fed_user_attribute USING btree (long_value_hash, name);


--
-- Name: fed_user_attr_long_values_lower_case; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX fed_user_attr_long_values_lower_case ON public.fed_user_attribute USING btree (long_value_hash_lower_case, name);


--
-- Name: idx_admin_event_time; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_admin_event_time ON public.admin_event_entity USING btree (realm_id, admin_event_time);


--
-- Name: idx_assoc_pol_assoc_pol_id; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_assoc_pol_assoc_pol_id ON public.associated_policy USING btree (associated_policy_id);


--
-- Name: idx_auth_config_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_auth_config_realm ON public.authenticator_config USING btree (realm_id);


--
-- Name: idx_auth_exec_flow; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_auth_exec_flow ON public.authentication_execution USING btree (flow_id);


--
-- Name: idx_auth_exec_realm_flow; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_auth_exec_realm_flow ON public.authentication_execution USING btree (realm_id, flow_id);


--
-- Name: idx_auth_flow_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_auth_flow_realm ON public.authentication_flow USING btree (realm_id);


--
-- Name: idx_cl_clscope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_cl_clscope ON public.client_scope_client USING btree (scope_id);


--
-- Name: idx_client_att_by_name_value; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_client_att_by_name_value ON public.client_attributes USING btree (name, substr(value, 1, 255));


--
-- Name: idx_client_id; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_client_id ON public.client USING btree (client_id);


--
-- Name: idx_client_init_acc_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_client_init_acc_realm ON public.client_initial_access USING btree (realm_id);


--
-- Name: idx_clscope_attrs; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_clscope_attrs ON public.client_scope_attributes USING btree (scope_id);


--
-- Name: idx_clscope_cl; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_clscope_cl ON public.client_scope_client USING btree (client_id);


--
-- Name: idx_clscope_protmap; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_clscope_protmap ON public.protocol_mapper USING btree (client_scope_id);


--
-- Name: idx_clscope_role; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_clscope_role ON public.client_scope_role_mapping USING btree (scope_id);


--
-- Name: idx_compo_config_compo; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_compo_config_compo ON public.component_config USING btree (component_id);


--
-- Name: idx_component_provider_type; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_component_provider_type ON public.component USING btree (provider_type);


--
-- Name: idx_component_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_component_realm ON public.component USING btree (realm_id);


--
-- Name: idx_composite; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_composite ON public.composite_role USING btree (composite);


--
-- Name: idx_composite_child; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_composite_child ON public.composite_role USING btree (child_role);


--
-- Name: idx_defcls_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_defcls_realm ON public.default_client_scope USING btree (realm_id);


--
-- Name: idx_defcls_scope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_defcls_scope ON public.default_client_scope USING btree (scope_id);


--
-- Name: idx_event_time; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_event_time ON public.event_entity USING btree (realm_id, event_time);


--
-- Name: idx_fedidentity_feduser; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fedidentity_feduser ON public.federated_identity USING btree (federated_user_id);


--
-- Name: idx_fedidentity_user; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fedidentity_user ON public.federated_identity USING btree (user_id);


--
-- Name: idx_fu_attribute; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_attribute ON public.fed_user_attribute USING btree (user_id, realm_id, name);


--
-- Name: idx_fu_cnsnt_ext; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_cnsnt_ext ON public.fed_user_consent USING btree (user_id, client_storage_provider, external_client_id);


--
-- Name: idx_fu_consent; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_consent ON public.fed_user_consent USING btree (user_id, client_id);


--
-- Name: idx_fu_consent_ru; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_consent_ru ON public.fed_user_consent USING btree (realm_id, user_id);


--
-- Name: idx_fu_credential; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_credential ON public.fed_user_credential USING btree (user_id, type);


--
-- Name: idx_fu_credential_ru; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_credential_ru ON public.fed_user_credential USING btree (realm_id, user_id);


--
-- Name: idx_fu_group_membership; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_group_membership ON public.fed_user_group_membership USING btree (user_id, group_id);


--
-- Name: idx_fu_group_membership_ru; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_group_membership_ru ON public.fed_user_group_membership USING btree (realm_id, user_id);


--
-- Name: idx_fu_required_action; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_required_action ON public.fed_user_required_action USING btree (user_id, required_action);


--
-- Name: idx_fu_required_action_ru; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_required_action_ru ON public.fed_user_required_action USING btree (realm_id, user_id);


--
-- Name: idx_fu_role_mapping; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_role_mapping ON public.fed_user_role_mapping USING btree (user_id, role_id);


--
-- Name: idx_fu_role_mapping_ru; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_fu_role_mapping_ru ON public.fed_user_role_mapping USING btree (realm_id, user_id);


--
-- Name: idx_group_att_by_name_value; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_group_att_by_name_value ON public.group_attribute USING btree (name, ((value)::character varying(250)));


--
-- Name: idx_group_attr_group; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_group_attr_group ON public.group_attribute USING btree (group_id);


--
-- Name: idx_group_role_mapp_group; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_group_role_mapp_group ON public.group_role_mapping USING btree (group_id);


--
-- Name: idx_id_prov_mapp_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_id_prov_mapp_realm ON public.identity_provider_mapper USING btree (realm_id);


--
-- Name: idx_ident_prov_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_ident_prov_realm ON public.identity_provider USING btree (realm_id);


--
-- Name: idx_idp_for_login; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_idp_for_login ON public.identity_provider USING btree (realm_id, enabled, link_only, hide_on_login, organization_id);


--
-- Name: idx_idp_realm_org; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_idp_realm_org ON public.identity_provider USING btree (realm_id, organization_id);


--
-- Name: idx_keycloak_role_client; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_keycloak_role_client ON public.keycloak_role USING btree (client);


--
-- Name: idx_keycloak_role_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_keycloak_role_realm ON public.keycloak_role USING btree (realm);


--
-- Name: idx_offline_uss_by_broker_session_id; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_offline_uss_by_broker_session_id ON public.offline_user_session USING btree (broker_session_id, realm_id);


--
-- Name: idx_offline_uss_by_last_session_refresh; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_offline_uss_by_last_session_refresh ON public.offline_user_session USING btree (realm_id, offline_flag, last_session_refresh);


--
-- Name: idx_offline_uss_by_user; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_offline_uss_by_user ON public.offline_user_session USING btree (user_id, realm_id, offline_flag);


--
-- Name: idx_org_domain_org_id; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_org_domain_org_id ON public.org_domain USING btree (org_id);


--
-- Name: idx_perm_ticket_owner; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_perm_ticket_owner ON public.resource_server_perm_ticket USING btree (owner);


--
-- Name: idx_perm_ticket_requester; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_perm_ticket_requester ON public.resource_server_perm_ticket USING btree (requester);


--
-- Name: idx_protocol_mapper_client; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_protocol_mapper_client ON public.protocol_mapper USING btree (client_id);


--
-- Name: idx_realm_attr_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_attr_realm ON public.realm_attribute USING btree (realm_id);


--
-- Name: idx_realm_clscope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_clscope ON public.client_scope USING btree (realm_id);


--
-- Name: idx_realm_def_grp_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_def_grp_realm ON public.realm_default_groups USING btree (realm_id);


--
-- Name: idx_realm_evt_list_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_evt_list_realm ON public.realm_events_listeners USING btree (realm_id);


--
-- Name: idx_realm_evt_types_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_evt_types_realm ON public.realm_enabled_event_types USING btree (realm_id);


--
-- Name: idx_realm_master_adm_cli; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_master_adm_cli ON public.realm USING btree (master_admin_client);


--
-- Name: idx_realm_supp_local_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_realm_supp_local_realm ON public.realm_supported_locales USING btree (realm_id);


--
-- Name: idx_redir_uri_client; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_redir_uri_client ON public.redirect_uris USING btree (client_id);


--
-- Name: idx_req_act_prov_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_req_act_prov_realm ON public.required_action_provider USING btree (realm_id);


--
-- Name: idx_res_policy_policy; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_res_policy_policy ON public.resource_policy USING btree (policy_id);


--
-- Name: idx_res_scope_scope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_res_scope_scope ON public.resource_scope USING btree (scope_id);


--
-- Name: idx_res_serv_pol_res_serv; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_res_serv_pol_res_serv ON public.resource_server_policy USING btree (resource_server_id);


--
-- Name: idx_res_srv_res_res_srv; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_res_srv_res_res_srv ON public.resource_server_resource USING btree (resource_server_id);


--
-- Name: idx_res_srv_scope_res_srv; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_res_srv_scope_res_srv ON public.resource_server_scope USING btree (resource_server_id);


--
-- Name: idx_rev_token_on_expire; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_rev_token_on_expire ON public.revoked_token USING btree (expire);


--
-- Name: idx_role_attribute; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_role_attribute ON public.role_attribute USING btree (role_id);


--
-- Name: idx_role_clscope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_role_clscope ON public.client_scope_role_mapping USING btree (role_id);


--
-- Name: idx_scope_mapping_role; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_scope_mapping_role ON public.scope_mapping USING btree (role_id);


--
-- Name: idx_scope_policy_policy; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_scope_policy_policy ON public.scope_policy USING btree (policy_id);


--
-- Name: idx_update_time; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_update_time ON public.migration_model USING btree (update_time);


--
-- Name: idx_usconsent_clscope; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_usconsent_clscope ON public.user_consent_client_scope USING btree (user_consent_id);


--
-- Name: idx_usconsent_scope_id; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_usconsent_scope_id ON public.user_consent_client_scope USING btree (scope_id);


--
-- Name: idx_user_attribute; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_attribute ON public.user_attribute USING btree (user_id);


--
-- Name: idx_user_attribute_name; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_attribute_name ON public.user_attribute USING btree (name, value);


--
-- Name: idx_user_consent; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_consent ON public.user_consent USING btree (user_id);


--
-- Name: idx_user_credential; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_credential ON public.credential USING btree (user_id);


--
-- Name: idx_user_email; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_email ON public.user_entity USING btree (email);


--
-- Name: idx_user_group_mapping; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_group_mapping ON public.user_group_membership USING btree (user_id);


--
-- Name: idx_user_reqactions; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_reqactions ON public.user_required_action USING btree (user_id);


--
-- Name: idx_user_role_mapping; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_role_mapping ON public.user_role_mapping USING btree (user_id);


--
-- Name: idx_user_service_account; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_user_service_account ON public.user_entity USING btree (realm_id, service_account_client_link);


--
-- Name: idx_usr_fed_map_fed_prv; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_usr_fed_map_fed_prv ON public.user_federation_mapper USING btree (federation_provider_id);


--
-- Name: idx_usr_fed_map_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_usr_fed_map_realm ON public.user_federation_mapper USING btree (realm_id);


--
-- Name: idx_usr_fed_prv_realm; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_usr_fed_prv_realm ON public.user_federation_provider USING btree (realm_id);


--
-- Name: idx_web_orig_client; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX idx_web_orig_client ON public.web_origins USING btree (client_id);


--
-- Name: user_attr_long_values; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX user_attr_long_values ON public.user_attribute USING btree (long_value_hash, name);


--
-- Name: user_attr_long_values_lower_case; Type: INDEX; Schema: public; Owner: admin
--

CREATE INDEX user_attr_long_values_lower_case ON public.user_attribute USING btree (long_value_hash_lower_case, name);


--
-- Name: identity_provider fk2b4ebc52ae5c3b34; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider
    ADD CONSTRAINT fk2b4ebc52ae5c3b34 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: client_attributes fk3c47c64beacca966; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_attributes
    ADD CONSTRAINT fk3c47c64beacca966 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: federated_identity fk404288b92ef007a6; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.federated_identity
    ADD CONSTRAINT fk404288b92ef007a6 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_node_registrations fk4129723ba992f594; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_node_registrations
    ADD CONSTRAINT fk4129723ba992f594 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: redirect_uris fk_1burs8pb4ouj97h5wuppahv9f; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.redirect_uris
    ADD CONSTRAINT fk_1burs8pb4ouj97h5wuppahv9f FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: user_federation_provider fk_1fj32f6ptolw2qy60cd8n01e8; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_provider
    ADD CONSTRAINT fk_1fj32f6ptolw2qy60cd8n01e8 FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_required_credential fk_5hg65lybevavkqfki3kponh9v; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_required_credential
    ADD CONSTRAINT fk_5hg65lybevavkqfki3kponh9v FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_attribute fk_5hrm2vlf9ql5fu022kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu022kqepovbr FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: user_attribute fk_5hrm2vlf9ql5fu043kqepovbr; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_attribute
    ADD CONSTRAINT fk_5hrm2vlf9ql5fu043kqepovbr FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: user_required_action fk_6qj3w1jw9cvafhe19bwsiuvmd; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_required_action
    ADD CONSTRAINT fk_6qj3w1jw9cvafhe19bwsiuvmd FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: keycloak_role fk_6vyqfe4cn4wlq8r6kt5vdsj5c; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.keycloak_role
    ADD CONSTRAINT fk_6vyqfe4cn4wlq8r6kt5vdsj5c FOREIGN KEY (realm) REFERENCES public.realm(id);


--
-- Name: realm_smtp_config fk_70ej8xdxgxd0b9hh6180irr0o; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_smtp_config
    ADD CONSTRAINT fk_70ej8xdxgxd0b9hh6180irr0o FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_attribute fk_8shxd6l3e9atqukacxgpffptw; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_attribute
    ADD CONSTRAINT fk_8shxd6l3e9atqukacxgpffptw FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: composite_role fk_a63wvekftu8jo1pnj81e7mce2; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_a63wvekftu8jo1pnj81e7mce2 FOREIGN KEY (composite) REFERENCES public.keycloak_role(id);


--
-- Name: authentication_execution fk_auth_exec_flow; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_flow FOREIGN KEY (flow_id) REFERENCES public.authentication_flow(id);


--
-- Name: authentication_execution fk_auth_exec_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authentication_execution
    ADD CONSTRAINT fk_auth_exec_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authentication_flow fk_auth_flow_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authentication_flow
    ADD CONSTRAINT fk_auth_flow_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: authenticator_config fk_auth_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.authenticator_config
    ADD CONSTRAINT fk_auth_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_role_mapping fk_c4fqv34p1mbylloxang7b1q3l; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_role_mapping
    ADD CONSTRAINT fk_c4fqv34p1mbylloxang7b1q3l FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: client_scope_attributes fk_cl_scope_attr_scope; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope_attributes
    ADD CONSTRAINT fk_cl_scope_attr_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_scope_role_mapping fk_cl_scope_rm_scope; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_scope_role_mapping
    ADD CONSTRAINT fk_cl_scope_rm_scope FOREIGN KEY (scope_id) REFERENCES public.client_scope(id);


--
-- Name: protocol_mapper fk_cli_scope_mapper; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_cli_scope_mapper FOREIGN KEY (client_scope_id) REFERENCES public.client_scope(id);


--
-- Name: client_initial_access fk_client_init_acc_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.client_initial_access
    ADD CONSTRAINT fk_client_init_acc_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: component_config fk_component_config; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.component_config
    ADD CONSTRAINT fk_component_config FOREIGN KEY (component_id) REFERENCES public.component(id);


--
-- Name: component fk_component_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.component
    ADD CONSTRAINT fk_component_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_default_groups fk_def_groups_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_default_groups
    ADD CONSTRAINT fk_def_groups_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_mapper_config fk_fedmapper_cfg; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_mapper_config
    ADD CONSTRAINT fk_fedmapper_cfg FOREIGN KEY (user_federation_mapper_id) REFERENCES public.user_federation_mapper(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_fedprv; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_fedprv FOREIGN KEY (federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_federation_mapper fk_fedmapperpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_mapper
    ADD CONSTRAINT fk_fedmapperpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: associated_policy fk_frsr5s213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsr5s213xcx4wnkog82ssrfy FOREIGN KEY (associated_policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrasp13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrasp13xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog82sspmt; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82sspmt FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_resource fk_frsrho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_resource
    ADD CONSTRAINT fk_frsrho213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog83sspmt; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog83sspmt FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_server_perm_ticket fk_frsrho213xcx4wnkog84sspmt; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrho213xcx4wnkog84sspmt FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: associated_policy fk_frsrpas14xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.associated_policy
    ADD CONSTRAINT fk_frsrpas14xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: scope_policy fk_frsrpass3xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.scope_policy
    ADD CONSTRAINT fk_frsrpass3xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_perm_ticket fk_frsrpo2128cx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_perm_ticket
    ADD CONSTRAINT fk_frsrpo2128cx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_server_policy fk_frsrpo213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_policy
    ADD CONSTRAINT fk_frsrpo213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: resource_scope fk_frsrpos13xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrpos13xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpos53xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpos53xcx4wnkog82ssrfy FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: resource_policy fk_frsrpp213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_policy
    ADD CONSTRAINT fk_frsrpp213xcx4wnkog82ssrfy FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: resource_scope fk_frsrps213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_scope
    ADD CONSTRAINT fk_frsrps213xcx4wnkog82ssrfy FOREIGN KEY (scope_id) REFERENCES public.resource_server_scope(id);


--
-- Name: resource_server_scope fk_frsrso213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_server_scope
    ADD CONSTRAINT fk_frsrso213xcx4wnkog82ssrfy FOREIGN KEY (resource_server_id) REFERENCES public.resource_server(id);


--
-- Name: composite_role fk_gr7thllb9lu8q4vqa4524jjy8; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.composite_role
    ADD CONSTRAINT fk_gr7thllb9lu8q4vqa4524jjy8 FOREIGN KEY (child_role) REFERENCES public.keycloak_role(id);


--
-- Name: user_consent_client_scope fk_grntcsnt_clsc_usc; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent_client_scope
    ADD CONSTRAINT fk_grntcsnt_clsc_usc FOREIGN KEY (user_consent_id) REFERENCES public.user_consent(id);


--
-- Name: user_consent fk_grntcsnt_user; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_consent
    ADD CONSTRAINT fk_grntcsnt_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: group_attribute fk_group_attribute_group; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.group_attribute
    ADD CONSTRAINT fk_group_attribute_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: group_role_mapping fk_group_role_group; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.group_role_mapping
    ADD CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES public.keycloak_group(id);


--
-- Name: realm_enabled_event_types fk_h846o4h0w8epx5nwedrf5y69j; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_enabled_event_types
    ADD CONSTRAINT fk_h846o4h0w8epx5nwedrf5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: realm_events_listeners fk_h846o4h0w8epx5nxev9f5y69j; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_events_listeners
    ADD CONSTRAINT fk_h846o4h0w8epx5nxev9f5y69j FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: identity_provider_mapper fk_idpm_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider_mapper
    ADD CONSTRAINT fk_idpm_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: idp_mapper_config fk_idpmconfig; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.idp_mapper_config
    ADD CONSTRAINT fk_idpmconfig FOREIGN KEY (idp_mapper_id) REFERENCES public.identity_provider_mapper(id);


--
-- Name: web_origins fk_lojpho213xcx4wnkog82ssrfy; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.web_origins
    ADD CONSTRAINT fk_lojpho213xcx4wnkog82ssrfy FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: scope_mapping fk_ouse064plmlr732lxjcn1q5f1; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.scope_mapping
    ADD CONSTRAINT fk_ouse064plmlr732lxjcn1q5f1 FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: protocol_mapper fk_pcm_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.protocol_mapper
    ADD CONSTRAINT fk_pcm_realm FOREIGN KEY (client_id) REFERENCES public.client(id);


--
-- Name: credential fk_pfyr0glasqyl0dei3kl69r6v0; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.credential
    ADD CONSTRAINT fk_pfyr0glasqyl0dei3kl69r6v0 FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: protocol_mapper_config fk_pmconfig; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.protocol_mapper_config
    ADD CONSTRAINT fk_pmconfig FOREIGN KEY (protocol_mapper_id) REFERENCES public.protocol_mapper(id);


--
-- Name: default_client_scope fk_r_def_cli_scope_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.default_client_scope
    ADD CONSTRAINT fk_r_def_cli_scope_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: required_action_provider fk_req_act_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.required_action_provider
    ADD CONSTRAINT fk_req_act_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: resource_uris fk_resource_server_uris; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.resource_uris
    ADD CONSTRAINT fk_resource_server_uris FOREIGN KEY (resource_id) REFERENCES public.resource_server_resource(id);


--
-- Name: role_attribute fk_role_attribute_id; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.role_attribute
    ADD CONSTRAINT fk_role_attribute_id FOREIGN KEY (role_id) REFERENCES public.keycloak_role(id);


--
-- Name: realm_supported_locales fk_supported_locales_realm; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.realm_supported_locales
    ADD CONSTRAINT fk_supported_locales_realm FOREIGN KEY (realm_id) REFERENCES public.realm(id);


--
-- Name: user_federation_config fk_t13hpu1j94r2ebpekr39x5eu5; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_federation_config
    ADD CONSTRAINT fk_t13hpu1j94r2ebpekr39x5eu5 FOREIGN KEY (user_federation_provider_id) REFERENCES public.user_federation_provider(id);


--
-- Name: user_group_membership fk_user_group_user; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.user_group_membership
    ADD CONSTRAINT fk_user_group_user FOREIGN KEY (user_id) REFERENCES public.user_entity(id);


--
-- Name: policy_config fkdc34197cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.policy_config
    ADD CONSTRAINT fkdc34197cf864c4e43 FOREIGN KEY (policy_id) REFERENCES public.resource_server_policy(id);


--
-- Name: identity_provider_config fkdc4897cf864c4e43; Type: FK CONSTRAINT; Schema: public; Owner: admin
--

ALTER TABLE ONLY public.identity_provider_config
    ADD CONSTRAINT fkdc4897cf864c4e43 FOREIGN KEY (identity_provider_id) REFERENCES public.identity_provider(internal_id);


--
-- PostgreSQL database dump complete
--

