import click


@click.command()
@click.option('--file-path', type=click.Path(resolve_path=True), help='Path to the file')
def process_file(file_path):
    click.echo(f"Processing file: {file_path}")


if __name__ == '__main__':
    process_file()
