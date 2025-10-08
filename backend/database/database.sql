-- WARNING: This schema is for context only and is not meant to be run.
-- Table order and constraints may not be valid for execution.

CREATE TABLE public.files (
  hash text NOT NULL,
  size integer NOT NULL,
  data bytea NOT NULL,
  occurance integer NOT NULL DEFAULT 0,
  CONSTRAINT files_pkey PRIMARY KEY (hash)
);
CREATE TABLE public.links (
  hash text NOT NULL,
  id text NOT NULL,
  access USER-DEFINED NOT NULL DEFAULT 'PRIVATE'::access_level,
  downloads integer NOT NULL DEFAULT 0,
  filename text NOT NULL,
  time timestamp without time zone NOT NULL,
  file_id integer NOT NULL DEFAULT 0,
  size integer NOT NULL CHECK (size > 0),
  CONSTRAINT links_pkey PRIMARY KEY (id, filename),
  CONSTRAINT links_hash_fkey FOREIGN KEY (hash) REFERENCES public.files(hash),
  CONSTRAINT links_id_fkey FOREIGN KEY (id) REFERENCES public.users(id) ON DELETE CASCADE
);
CREATE TABLE public.users (
  id text NOT NULL CHECK (length(id) <= 50 AND length(id) >= 5),
  pwd text NOT NULL,
  sizeused integer NOT NULL DEFAULT 0,
  isadmin boolean NOT NULL DEFAULT false,
  CONSTRAINT users_pkey PRIMARY KEY (id)
);


-- Adding triggers on file and user on insert in Link

CREATE OR REPLACE FUNCTION update_file_user_on_link_insert()
RETURNS TRIGGER AS $$
BEGIN
    -- 1. Increment file occurrence
    UPDATE public.files
    SET occurance = occurance + 1
    WHERE hash = NEW.hash;

    -- 2. Increment user's sizeused by the file size
    UPDATE public.users
    SET sizeused = sizeused + (
        SELECT size FROM public.files WHERE hash = NEW.hash
    )
    WHERE id = NEW.id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER link_insert_trigger
AFTER INSERT ON public.links
FOR EACH ROW
EXECUTE FUNCTION update_file_user_on_link_insert();





-- Adding triggers to generate the unique file_id

CREATE OR REPLACE FUNCTION assign_file_id()
RETURNS TRIGGER AS $$
DECLARE
    next_fid integer;
BEGIN
    -- Find the first missing file_id for this user (id)
    SELECT COALESCE(
        MIN(gs),
        COALESCE(MAX(l.file_id), 0) + 1
    )
    INTO next_fid
    FROM generate_series(1, COALESCE((SELECT MAX(file_id) 
                                      FROM public.links 
                                      WHERE id = NEW.id), 0) + 1) gs
    WHERE NOT EXISTS (
        SELECT 1 FROM public.links l 
        WHERE l.id = NEW.id AND l.file_id = gs
    );

    NEW.file_id := next_fid;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_assign_file_id
BEFORE INSERT ON public.links
FOR EACH ROW
EXECUTE FUNCTION assign_file_id();



-- Adding triggers to decrement and/or clean up file and update users

CREATE OR REPLACE FUNCTION after_delete_links()
RETURNS TRIGGER AS $$
BEGIN
  -- Subtract size from user
  UPDATE users
  SET sizeused = sizeused - OLD.size
  WHERE id = OLD.id AND EXISTS (SELECT 1 FROM users WHERE id = OLD.id);

  -- Decrement occurance in files
  UPDATE files
  SET occurance = occurance - 1
  WHERE hash = OLD.hash;

  -- If occurance reaches 0, delete file
  DELETE FROM files
  WHERE hash = OLD.hash AND occurance <= 0;

  RETURN OLD;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_after_delete_links
AFTER DELETE ON links
FOR EACH ROW
EXECUTE FUNCTION after_delete_links();