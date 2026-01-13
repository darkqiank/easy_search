-- Drop table

-- DROP TABLE public.vt_comments;

CREATE TABLE public.vt_comments (
	id text NOT NULL,
	"content" text NULL,
	tags text NULL,
	votes jsonb NULL,
	src_id text NULL,
	src_type text NULL,
	src_content text NULL,
	author_id text NULL,
	comment_date timestamp NULL,
	create_time timestamp NULL,
	CONSTRAINT vt_comments_pkey PRIMARY KEY (id)
);

-- public.vt_reports definition

-- Drop table

-- DROP TABLE public.vt_reports;

CREATE TABLE public.vt_reports (
	id text NOT NULL,
	"data" jsonb NULL,
	create_time timestamp NULL,
	CONSTRAINT vt_reports_pkey PRIMARY KEY (id)
);

-- public.whois_info definition

-- Drop table

-- DROP TABLE public.whois_info;

CREATE TABLE public.whois_info (
	"domain" varchar(255) NOT NULL,
	"data" jsonb NULL,
	"level" int4 DEFAULT 0 NOT NULL,
	insert_time timestamp DEFAULT CURRENT_TIMESTAMP NULL,
	CONSTRAINT whois_info_pkey PRIMARY KEY (domain)
);